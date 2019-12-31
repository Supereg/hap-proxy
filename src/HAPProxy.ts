import {HAPClient, HAPClientEvents} from "./HAPClient";
import {HAPServer, HAPServerConnection, HAPServerEvents, HTTPServerResponseCallback} from "./HAPServer";
import {HTTPContentType, HTTPResponse, HTTPServerResponse, HTTPStatus} from "./lib/http-protocol";
import {ParsedUrlQuery} from "querystring";
import {ProtocolInformationServiceFilter} from "./filters";
import {ServiceType} from "./definitions";
import {
    AttributeDatabase,
    CharacteristicsReadResponse,
    CharacteristicsWriteRequest,
    CharacteristicsWriteResponse
} from "./types/hap-proxy";
import {IdentifierCache} from "./storage/IdentifierCache";
import assert from "assert";
import {uuid} from "./utils/uuid";

export abstract class ServiceFilter {

    readonly context: HAPProxy;
    readonly aid: number; // accessory id the service is associated with
    readonly iid: number; // instance id of the service an instance of this filter is used for

    // record holding the actual filter instances; indexed by iid (iid of the characteristic)
    readonly characteristicsFilters: Record<number, CharacteristicFilter<any>> = {};

    /**
     * Record of filter definitions. Key is the CharacteristicType and value the constructor of the CharacteristicFilter.
     */
    abstract characteristicFilterDefinitions: Record<string, CharacteristicFilterConstructor<any>>;

    public constructor(context: HAPProxy, aid: number, iid: number) {
        this.context = context;
        this.aid = aid;
        this.iid = iid;
    }

}

/**
 * Read/write (with write response) characteristic filter
 */
export abstract class CharacteristicFilter<T> {

    readonly context: HAPProxy;
    readonly parent: ServiceFilter;
    readonly iid: number; // instance id of the characteristic

    public constructor(context: HAPProxy, parent: ServiceFilter, iid: number) {
        this.context = context;
        this.parent = parent;
        this.iid = iid;
    }

    abstract filterRead(connection: HAPServerConnection, readValue: T): Promise<T>;

    abstract filterWrite(connection: HAPServerConnection, writtenValue: T): Promise<T>;

    abstract filterWriteResponse(connection: HAPServerConnection, writeResponseValue: T): Promise<T>;

}

/**
 * Read/write characteristic filter
 */
export abstract class CharacteristicFilterRW<T> extends CharacteristicFilter<T> {

    async filterWriteResponse(connection: HAPServerConnection, writeResponseValue: T): Promise<T> {
        return writeResponseValue;
    }

}

/**
 * Read only characteristic filter
 */
export abstract class CharacteristicFilterR<T> extends CharacteristicFilterRW<T> {

    async filterWrite(connection: HAPServerConnection, writtenValue: T): Promise<T> {
        return writtenValue; // its not allowed so just forward it. Client will return an error
    }

}

/**
 * Write only characteristic filter
 */
export abstract class CharacteristicFilterW<T> extends CharacteristicFilterRW<T> {

    async filterRead(connection: HAPServerConnection, readValue: T): Promise<T> {
        return readValue;
    }

}

/**
 * Control point characteristic filter
 */
export abstract class CharacteristicFilterControlPoint<T> extends CharacteristicFilter<T> {

    async filterRead(connection: HAPServerConnection, readValue: T): Promise<T> {
        return readValue;
    }

}

export interface ServiceFilterConstructor {

    /**
     * Creates a new instance of a ServiceFilter
     *
     * @param context {HAPProxy} - the associated proxy instance
     * @param aid {number} - accessory id
     * @param iid {number} - instance id of the service
     */
    new(context: HAPProxy, aid: number, iid: number): ServiceFilter;

}

export interface CharacteristicFilterConstructor<T> {

    /**
     * Creates a new instance of a CharacteristicFilter
     *
     * @param context {HAPProxy} - the associated proxy instance
     * @param parent {ServiceFilter} - the associated ServiceFilter instance
     * @param iid {number} - instance id of the characteristic
     */
    new(context: HAPProxy, parent: ServiceFilter, iid: number): CharacteristicFilter<T>;

}

export class HAPProxy {

    // TODO disconnect from client when last session disconnects from server
    // TODO unpair from client when server gets unpaired

    // TODO do we want a 1:1 mapping of connections? HAPClient would need to support multiple connections

    // TODO monitor configuration number and increment our own
    client: HAPClient;
    server: HAPServer;

    identifierCache: IdentifierCache;

    serviceFilterDefinitions: Record<string, ServiceFilterConstructor> = {}; // indexed by the ServiceType (uuid)
    private serviceFilters: Record<string, ServiceFilter> = {}; // indexed by "aid.iid" (iid of the service)

    constructor(client: HAPClient, server: HAPServer) {
        this.client = client;
        this.server = server;

        this.identifierCache = new IdentifierCache(this.client.clientInfo.clientId); // TODO load from disk

        this.addServiceFilter(ServiceType.PROTOCOL_INFORMATION, ProtocolInformationServiceFilter);
        // TODO this.addServiceFilter(ServiceType.DATA_STREAM_TRANSPORT_MANAGEMENT, DataStreamTransportManagementServiceFilter);

        this.server.on(HAPServerEvents.ACCESSORIES, this.handleServerAccessories.bind(this));
        this.server.on(HAPServerEvents.GET_CHARACTERISTICS, this.handleServerGetCharacteristics.bind(this));
        this.server.on(HAPServerEvents.SET_CHARACTERISTICS, this.handleServerSetCharacteristics.bind(this));
        this.server.on(HAPServerEvents.PREPARE_WRITE, this.handleServerPrepareWrite.bind(this));
        this.server.on(HAPServerEvents.RESOURCE, this.handleServerResource.bind(this));

        this.client.on(HAPClientEvents.EVENT_RAW, this.handleAccessoryEvent.bind(this));
    }

    addServiceFilter(serviceType: ServiceType, filterDefinition: ServiceFilterConstructor) {
        this.serviceFilterDefinitions[serviceType] = filterDefinition;
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

    private handleAccessoryEvent(eventBuf: Buffer) {
        console.log("Received event which needs to be forwarded!");
        // TODO track what connections are subscribed to which characteristics events
    }

    private handleServerAccessories(connection: HAPServerConnection, callback: HTTPServerResponseCallback) {
        this.client.accessories()
            .then(httpResponse => {
                if (httpResponse.status !== 200) {
                    callback(undefined, HAPProxy.responseToServerResponse(httpResponse));
                    return;
                }

                let chain = Promise.resolve();

                this.identifierCache.rebuild(); // clear cache before we rebuild it
                // TODO check if any services got removed and then remove the appropriate service filter

                const attributeDatabase: AttributeDatabase = JSON.parse(httpResponse.body.toString());
                // console.log(attributeDatabase); // TODO remove

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

                            const filter = this.getOrCreateCharacteristicFilter(serviceFilter, characteristic.iid, characteristic.type);

                            if (characteristic.value) { // only need to filter if we actually return a value
                                if (filter) {
                                    chain = chain
                                        .then(() => filter.filterRead(connection, characteristic.value))
                                        .then(value => characteristic.value = value)
                                        .catch(reason => console.log("Filter caused error: " + reason)); // TODO adjust message
                                }
                            }
                        });
                    });
                });

                return chain
                    .then(() => this.identifierCache.save())
                    .then(() => {
                        httpResponse.body = Buffer.from(JSON.stringify(attributeDatabase));
                        callback(undefined, HAPProxy.responseToServerResponse(httpResponse))
                    });
            })
            .catch(reason => callback(new Error(reason)));
    }

    private handleServerGetCharacteristics(connection: HAPServerConnection, ids: ParsedUrlQuery, callback: HTTPServerResponseCallback) {
        this.client.getCharacteristicsRaw(ids)
            .then(httpResponse => {
                if (httpResponse.status !== 200) {
                    callback(undefined, HAPProxy.responseToServerResponse(httpResponse));
                    return;
                }

                let chain = Promise.resolve();

                let rebuildResponse = false;
                const response: CharacteristicsReadResponse = JSON.parse(httpResponse.body.toString());
                // console.log(response); // TODO remove

                response.characteristics.forEach(characteristic => {
                    const filter = this.getCharacteristicFilter(characteristic.aid, characteristic.iid);

                    if (filter) {
                        const previousValue = characteristic.value;

                        chain = chain
                            .then(() => filter.filterRead(connection, previousValue))
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
        let chain = Promise.resolve();

        let rebuildRequest = false;
        let containsWriteResponse = false;

        const request: CharacteristicsWriteRequest = JSON.parse(writeRequest.toString());

        request.characteristics.forEach(characteristic => {
            if (characteristic.value) {
                const filter = this.getCharacteristicFilter(characteristic.aid, characteristic.iid);

                if (filter) {
                    const previousValue = characteristic.value;

                    chain = chain
                        .then(() => filter.filterWrite(connection, previousValue))
                        .then(value => {
                            characteristic.value = value;

                            if (previousValue !== value) {
                                rebuildRequest = true;
                            }
                        })
                        .catch(reason => console.log("Filter caused error: " + reason)); // TODO adjust message
                }
            }

            if (characteristic.ev !== undefined) {
                // TODO track event subscriptions
                //  track disconnection to unsubscribe from events (1:1 matching of connections)
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
            .then(() => this.client.setCharacteristicsRaw(writeRequest))
            .then(httpResponse => {
                let chain = Promise.resolve();
                let rebuildResponse = false;

                if (containsWriteResponse) { // only decode response if we actually queried an control point characteristic
                    if (httpResponse.status === HTTPStatus.MULTI_STATUS) { // prop. some none spec compliant accessory
                        console.log("WARNING: The accessory returned unexpected http status (" +
                            HTTPStatus[httpResponse.status] + "/" + httpResponse.status + ") when we where expecting a write response!");
                        return;
                    }

                    const response: CharacteristicsWriteResponse = JSON.parse(httpResponse.body.toString());

                    response.characteristics.forEach(characteristic => {
                        if (characteristic.status !== 0 || characteristic.value === undefined) {
                            return;
                        }

                        const filter = this.getCharacteristicFilter(characteristic.aid, characteristic.iid);
                        if (filter) {
                            const previousValue = characteristic.value;

                            chain = chain
                                .then(() => filter.filterWriteResponse(connection, previousValue))
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
        // TODO track pids and ensure writes are correctly authenticated
        this.client.prepareWriteRaw(prepareRequest)
            .then(response => {
                callback(undefined, HAPProxy.responseToServerResponse(response));
            })
            .catch(reason => callback(new Error(reason)));
    }

    private handleServerResource(connection: HAPServerConnection, resourceRequest: Buffer, callback: HTTPServerResponseCallback) {
        this.client.resourceRaw(resourceRequest)
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
