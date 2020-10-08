import assert from "assert";
import {ParsedUrlQuery} from "querystring";
import {CharacteristicTypes, ServiceType, ServiceTypes} from "./definitions";
import {AccessoryInformationServiceFilter, DataStreamTransportManagementServiceFilter} from "./filters";
import {CharacteristicFilter} from "./filters/CharacteristicFilter";
import {ServiceFilter, ServiceFilterConstructor} from "./filters/ServiceFilter";
import {HAPClient, HAPClientConnection, HAPClientConnectionEvents, HAPClientEvents} from "./HAPClient";
import {
    HAPServer,
    HAPServerConnection,
    HAPServerConnectionEvents,
    HAPServerEvents,
    HTTPServerResponseCallback
} from "./HAPServer";
import {HTTPContentType, HTTPResponse, HTTPServerResponse, HTTPStatus} from "./lib/http-protocol";
import {AccessoryInfo} from "./storage/AccessoryInfo";
import {ClientInfo} from "./storage/ClientInfo";
import {IdentifierCache} from "./storage/IdentifierCache";
import {
    AttributeDatabase,
    CharacteristicsReadResponse,
    CharacteristicsWriteRequest,
    CharacteristicsWriteResponse,
    EventNotification,
    HAPStatusCode
} from "./types/hap-proxy";
import {uuid} from "./utils/uuid";

export class HAPProxy {

    readonly client: HAPClient;
    readonly server: HAPServer;

    readonly identifierCache: IdentifierCache;

    serviceFilterDefinitions: Record<string, ServiceFilterConstructor> = {}; // indexed by the ServiceType (uuid)
    private serviceFilters: Record<string, ServiceFilter> = {}; // indexed by "aid.iid" (iid of the service)

    serverToClientConnections: Record<string, HAPClientConnection> = {};

    constructor(clientInfo: ClientInfo, accessoryInfo: AccessoryInfo) {
        this.client = new HAPClient(clientInfo);
        this.server = new HAPServer(accessoryInfo);

        this.identifierCache = new IdentifierCache(this.client.clientInfo);

        this.addServiceFilter(ServiceType.PROTOCOL_INFORMATION, AccessoryInformationServiceFilter);
        this.addServiceFilter(ServiceType.DATA_STREAM_TRANSPORT_MANAGEMENT, DataStreamTransportManagementServiceFilter);

        this.server.on(HAPServerEvents.CONNECTION, this.handleServerConnection.bind(this));
        this.server.on(HAPServerEvents.UNPAIRED, this.handleServerUnpaired.bind(this));

        this.server.on(HAPServerEvents.ACCESSORIES, this.handleServerAccessories.bind(this));
        this.server.on(HAPServerEvents.GET_CHARACTERISTICS, this.handleServerGetCharacteristics.bind(this));
        this.server.on(HAPServerEvents.SET_CHARACTERISTICS, this.handleServerSetCharacteristics.bind(this));
        this.server.on(HAPServerEvents.PREPARE_WRITE, this.handleServerPrepareWrite.bind(this));
        this.server.on(HAPServerEvents.RESOURCE, this.handleServerResource.bind(this));

        this.client.on(HAPClientEvents.CONFIG_NUMBER_CHANGE, (num: number) => {
            this.server.accessoryInfo.updateConfigNumber(num)
                .then(() => this.server.advertiser.updateAdvertisement());
        });
    }

    listen(targetPort?: number) {
        this.identifierCache.load()
            .then(() => this.buildFiltersFromCache())
            .then(() => this.server.listen(targetPort))
            .then(() => this.client.bonjourBrowser.deviceInfoPromise())
            .then(info => this.server.accessoryInfo.initWithClientInfo(info))
            .then(() => this.server.advertiser.updateAdvertisement());
        // TODO add catch? would get thrown if client is not on network
    }

    addServiceFilter(serviceType: ServiceType, filterDefinition: ServiceFilterConstructor) {
        this.serviceFilterDefinitions[serviceType] = filterDefinition;
    }

    private buildFiltersFromCache() {
        let built = 0;
        this.identifierCache.entries().forEach(entry => {
            const serviceFilter = this.getOrCreateServiceFilter(entry.aid, entry.serviceIid, entry.serviceType);

            if (serviceFilter) {
                const filter = this.getOrCreateCharacteristicFilter(serviceFilter, entry.characteristicIid, entry.characteristicType);
                if (filter) {
                    built++;
                }
            }
        });

        if (built > 0) {
            console.log("Constructed " + built + " characteristic filters from IdentifierCache!"); // TODO debug
        }
    }

    private getOrCreateServiceFilter(aid: number, iid: number, type: string): ServiceFilter | undefined {
        let filterInstance = this.serviceFilters[aid + "." + iid];

        if (!filterInstance) { // check if we have a definition for this service. If we have create a new instance from it.
            const definition = this.serviceFilterDefinitions[type];

            if (definition) {
                filterInstance = new definition(this, aid, iid);
                this.serviceFilters[aid + "." + iid] = filterInstance;
            } else {
                return undefined; // no filter for this service type defined
            }
        }

        return filterInstance;
    }

    private getOrCreateCharacteristicFilter(parent: ServiceFilter, iid: number, type: string): CharacteristicFilter<any> | undefined {
        let filterInstance = parent.characteristicsFilters[iid];

        if (!filterInstance) {
            const definition = parent.characteristicFilterDefinitions[type];

            if (definition) {
                filterInstance = new definition(this, parent, iid);
                parent.characteristicsFilters[iid] = filterInstance;
            } else {
                return undefined; // no filter for this characteristic type defined
            }
        }

        return filterInstance;
    }

    private getCharacteristicFilter(aid: number, iid: number): CharacteristicFilter<any> | undefined {
        // iid passed to this method is the instance id of the characteristic

        const serviceIid = this.identifierCache.lookupServiceIid(aid, iid);
        // something heavily went wrong if this entry is not in the cache
        assert(serviceIid !== undefined, "Corrupted identifierCache. iid of service not found");

        const serviceFilter = this.serviceFilters[aid + "." + serviceIid];
        if (!serviceFilter) {
            return undefined;
        }

        return serviceFilter.characteristicsFilters[iid];
    }

    private handleServerConnection(serverConnection: HAPServerConnection) {
        const clientConnection = this.client.newConnection();

        this.serverToClientConnections[serverConnection.sessionID] = clientConnection;

        clientConnection.on(HAPClientConnectionEvents.EVENT_RAW, this.forwardEvent.bind(this, serverConnection));
        clientConnection.on(HAPClientConnectionEvents.DISCONNECTED, this.handleClientDisconnected.bind(this, serverConnection));

        clientConnection.ensureConnected().catch(reason => {
            console.log("Terminating server connection again since client could not be connected: " + reason); // TODO adjust message
            this.handleClientDisconnected(serverConnection);
        });

        serverConnection.on(HAPServerConnectionEvents.DISCONNECTED, this.handleServerDisconnected.bind(this, serverConnection, clientConnection));
    }

    private handleServerUnpaired() {
        // noinspection JSIgnoredPromiseFromCall
        this.client.newConnection().removePairing();
    }

    private forwardEvent(serverConnection: HAPServerConnection, eventBuf: Buffer) {
        const event: EventNotification = JSON.parse(eventBuf.toString());
        event.characteristics.forEach(characteristic => {
            const type = this.identifierCache.lookupType(characteristic.aid, characteristic.iid);
            const serviceName = ServiceTypes.TYPE_TO_NAME[type.serviceType];
            const characteristicName = CharacteristicTypes.TYPE_TO_NAME[type.characteristicType];
            console.log(new Date().toISOString() + " Event sent for " + serviceName + "." + characteristicName + " with value '" + characteristic.value + "'");
        });

        serverConnection.sendRawEvent(eventBuf);
    }

    private handleClientDisconnected(serverConnection: HAPServerConnection) {
        serverConnection.disconnect();
        delete this.serverToClientConnections[serverConnection.sessionID];
    }

    private handleServerDisconnected(serverConnection: HAPServerConnection, clientConnection: HAPClientConnection) {
        clientConnection.disconnect();
        delete this.serverToClientConnections[serverConnection.sessionID];
    }

    private matchConnections(connection: HAPServerConnection) {
        return this.serverToClientConnections[connection.sessionID];
    }

    private handleServerAccessories(connection: HAPServerConnection, callback: HTTPServerResponseCallback) {
        const clientConnection = this.matchConnections(connection);
        clientConnection.accessories()
            .then(httpResponse => {
                if (httpResponse.status !== 200) {
                    callback(undefined, HAPProxy.responseToServerResponse(httpResponse));
                    return;
                }

                let chain = Promise.resolve();

                this.identifierCache.rebuild(); // clear cache before we rebuild it
                // TODO check if any services got removed and then remove the appropriate service filter

                const attributeDatabase: AttributeDatabase = JSON.parse(httpResponse.body.toString());

                attributeDatabase.accessories.forEach(accessory => {
                    accessory.services.forEach(service => {
                        const serviceType = uuid.toLongForm(service.type);
                        const serviceFilter = this.getOrCreateServiceFilter(accessory.aid, service.iid, serviceType);

                        service.characteristics.forEach(characteristic => {
                            const characteristicType = uuid.toLongForm(characteristic.type);
                            this.identifierCache.persists(accessory.aid, service.iid, characteristic.iid, serviceType, characteristicType);

                            if (!serviceFilter) {
                                return;
                            }

                            const filter = this.getOrCreateCharacteristicFilter(serviceFilter, characteristic.iid, characteristicType);

                            if (characteristic.value) { // only need to filter if we actually return a value
                                if (filter) {
                                    chain = chain
                                        .then(() => filter.filterRead(connection, clientConnection, characteristic.value))
                                        .then(value => characteristic.value = value)
                                        .catch(reason => console.log("Filter caused error: " + reason)); // TODO adjust message
                                }
                            }
                        });
                    });
                });

                const body = JSON.stringify(attributeDatabase);
                console.log(new Date().toISOString() + " attributeDatabase: " + body);

                return chain
                    .then(() => this.identifierCache.save())
                    .then(() => {
                        httpResponse.body = Buffer.from(body);
                        callback(undefined, HAPProxy.responseToServerResponse(httpResponse))
                    });
            })
            .catch(reason => callback(new Error(reason)));
    }

    private handleServerGetCharacteristics(connection: HAPServerConnection, ids: ParsedUrlQuery, callback: HTTPServerResponseCallback) {
        const clientConnection = this.matchConnections(connection);
        clientConnection.getCharacteristicsRaw(ids)
            .then(httpResponse => {
                if (httpResponse.status !== 200) {
                    callback(undefined, HAPProxy.responseToServerResponse(httpResponse));
                    return;
                }

                let chain = Promise.resolve();

                let rebuildResponse = false;
                const response: CharacteristicsReadResponse = JSON.parse(httpResponse.body.toString());

                response.characteristics.forEach(characteristic => {
                    const type = this.identifierCache.lookupType(characteristic.aid, characteristic.iid);
                    const serviceName = ServiceTypes.TYPE_TO_NAME[type.serviceType];
                    const characteristicName = CharacteristicTypes.TYPE_TO_NAME[type.characteristicType];
                    console.log(new Date().toISOString() + " " + serviceName + "." + characteristicName + " was read to be '" + characteristic.value + "'");

                    const filter = this.getCharacteristicFilter(characteristic.aid, characteristic.iid);

                    if (filter) {
                        const previousValue = characteristic.value;

                        chain = chain
                            .then(() => filter.filterRead(connection, clientConnection, previousValue))
                            .then(value => {
                                characteristic.value = value;

                                if (previousValue !== value) {
                                    rebuildResponse = true;
                                }
                            })
                            .catch(reason => console.log("Filter caused error: " + reason)); // TODO adjust message
                    }
                });

                return chain.then(() => {
                        if (rebuildResponse) {
                            httpResponse.body = Buffer.from(JSON.stringify(response));
                        }

                        callback(undefined, HAPProxy.responseToServerResponse(httpResponse));
                    });
            })
            .catch(reason => callback(new Error(reason)));
    }

    private handleServerSetCharacteristics(connection: HAPServerConnection, writeRequest: Buffer, callback: HTTPServerResponseCallback) {
        const clientConnection = this.matchConnections(connection);

        let chain = Promise.resolve();

        let rebuildRequest = false;
        let containsWriteResponse = false;

        const request: CharacteristicsWriteRequest = JSON.parse(writeRequest.toString());

        request.characteristics.forEach(characteristic => {
            if (characteristic.value !== undefined) {
                const type = this.identifierCache.lookupType(characteristic.aid, characteristic.iid);
                const serviceName = ServiceTypes.TYPE_TO_NAME[type.serviceType];
                const characteristicName = CharacteristicTypes.TYPE_TO_NAME[type.characteristicType];
                console.log(new Date().toISOString() + " " + serviceName + "." + characteristicName + " was set to '" + characteristic.value + "'");

                const filter = this.getCharacteristicFilter(characteristic.aid, characteristic.iid);

                if (filter) {
                    const previousValue = characteristic.value;

                    chain = chain
                        .then(() => filter.filterWrite(connection, clientConnection, previousValue))
                        .then(value => {
                            characteristic.value = value;

                            if (previousValue !== value) {
                                rebuildRequest = true;
                            }
                        })
                        .catch(reason => console.log("Filter caused error: " + reason)); // TODO adjust message
                }
            }

            if (characteristic.r) {
                containsWriteResponse = true;
            }
        });

        chain
            .then(() => {
                if (rebuildRequest) {
                    writeRequest = Buffer.from(JSON.stringify(request));
                }
            })
            .then(() => clientConnection.setCharacteristicsRaw(writeRequest))
            .then(httpResponse => {
                let chain = Promise.resolve();
                let rebuildResponse = false;

                if (containsWriteResponse) { // only decode response if we actually queried an control point characteristic
                    if (httpResponse.status !== HTTPStatus.MULTI_STATUS) { // prop. some none spec compliant accessory
                        console.log("WARNING: The accessory returned unexpected http status (" +
                            HTTPStatus[httpResponse.status] + "/" + httpResponse.status + ") when we where expecting a write response!");
                        return;
                    }

                    const response: CharacteristicsWriteResponse = JSON.parse(httpResponse.body.toString());

                    response.characteristics.forEach(characteristic => {
                        if (characteristic.status !== 0) {
                            console.log("Got an error for our put request: " + HAPStatusCode[characteristic.status]); // TODO message
                            return;
                        }
                        if (characteristic.value === undefined) {
                            return;
                        }

                        const type = this.identifierCache.lookupType(characteristic.aid, characteristic.iid);
                        const serviceName = ServiceTypes.TYPE_TO_NAME[type.serviceType];
                        const characteristicName = CharacteristicTypes.TYPE_TO_NAME[type.characteristicType];
                        console.log(serviceName + "." + characteristicName + " write response was '" + characteristic.value + "'");

                        const filter = this.getCharacteristicFilter(characteristic.aid, characteristic.iid);
                        if (filter) {
                            const previousValue = characteristic.value;

                            chain = chain
                                .then(() => filter.filterWriteResponse(connection, clientConnection, previousValue))
                                .then(value => {
                                    characteristic.value = value;

                                    if (previousValue !== value) {
                                        rebuildResponse = true;
                                    }
                                })
                                .catch(reason => console.log("Filter caused error: " + reason)); // TODO adjust message
                        }
                    });

                    chain.then(() => {
                        if (rebuildResponse) {
                            httpResponse.body = Buffer.from(JSON.stringify(response));
                        }
                    });
                }

                return chain.then(() => callback(undefined, HAPProxy.responseToServerResponse(httpResponse)));
            })
            .catch(reason => callback(new Error(reason)));
    }

    private handleServerPrepareWrite(connection: HAPServerConnection, prepareRequest: Buffer, callback: HTTPServerResponseCallback) {
        // TODO adding ability to filter those too?
        this.matchConnections(connection).prepareWriteRaw(prepareRequest)
            .then(response => {
                callback(undefined, HAPProxy.responseToServerResponse(response));
            })
            .catch(reason => callback(new Error(reason)));
    }

    private handleServerResource(connection: HAPServerConnection, resourceRequest: Buffer, callback: HTTPServerResponseCallback) {
        // TODO adding ability to filter those too?
        this.matchConnections(connection).resourceRaw(resourceRequest)
            .then(response => {
                callback(undefined, HAPProxy.responseToServerResponse(response));
            })
            .catch(reason => callback(new Error(reason)));
    }

    private static responseToServerResponse(response: HTTPResponse): HTTPServerResponse {
        const contentType = response.headers["Content-Type"] as HTTPContentType;
        delete response.headers["Content-Type"];

        return {
            status: response.status,
            contentType: contentType,
            headers: {},
            data: response.body,
        };
    }

}
