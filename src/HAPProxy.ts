import {HAPClient, HAPClientEvents} from "./HAPClient";
import {HAPServer, HAPServerConnection, HAPServerEvents, HTTPServerResponseCallback} from "./HAPServer";
import {HTTPContentType, HTTPResponse, HTTPServerResponse} from "./lib/http-protocol";
import {ParsedUrlQuery} from "querystring";
import {DataStreamTransportManagementServiceFilter, ProtocolInformationServiceFilter} from "./filters";
import {ServiceType} from "./definitions";
import {AttributeDatabase, CharacteristicsSetRequest, CharacteristicsSetResponse} from "./types/hap-proxy";
import {IdentifierCache} from "./storage/IdentifierCache";

export abstract class ServiceFilter {

    context: HAPProxy;

    abstract serviceType: ServiceType;
    characteristicsFilters: Record<string, CharacteristicFilterRW<any>> = {}; // some predefined characteristic uuids are defined CharacteristicType

    public constructor(context: HAPProxy) {
        this.context = context;
    }

    abstract init(): void; // used to register characteristicsFilters

}

/**
 * Read/write (with write response) characteristic filter
 */
export abstract class CharacteristicFilter<T> {

    context: HAPProxy;

    public constructor(context: HAPProxy) {
        this.context = context;
    }

    abstract filterRead(connection: HAPServerConnection, readValue: T): T;

    abstract filterWrite(connection: HAPServerConnection, writtenValue: T): T;

    abstract filterWriteResponse(connection: HAPServerConnection, writeResponseValue: T): T;

}

/**
 * Read/write characteristic filter
 */
export abstract class CharacteristicFilterRW<T> extends CharacteristicFilter<T> {

    filterWriteResponse(connection: HAPServerConnection, writeResponseValue: T): T {
        return writeResponseValue;
    }

}

/**
 * Read only characteristic filter
 */
export abstract class CharacteristicFilterR<T> extends CharacteristicFilterRW<T> {

    filterWrite(connection: HAPServerConnection, writtenValue: T): T {
        return writtenValue; // its not allowed so just forward it. Client will return an error
    }

}

/**
 * Write only characteristic filter
 */
export abstract class CharacteristicFilterW<T> extends CharacteristicFilterRW<T> {

    filterRead(connection: HAPServerConnection, readValue: T): T {
        return readValue;
    }

}

/**
 * Control point characteristic filter
 */
export abstract class CharacteristicFilterControlPoint<T> extends CharacteristicFilter<T> {

    filterRead(connection: HAPServerConnection, readValue: T): T {
        return readValue;
    }

}

export class HAPProxy {

    // TODO disconnect from client when last session disconnects from server
    // TODO unpair from client when server gets unpaired

    // TODO do we want a 1:1 mapping of connections? HAPClient would need to support multiple connections

    // TODO monitor configuration number and increment our own
    client: HAPClient;
    server: HAPServer;

    identifierCache: IdentifierCache;

    serviceFilters: Record<string, ServiceFilter> = {}; // some predefined service uuids are defined CharacteristicType

    // TODO identifier cache: map aid.iid to type

    constructor(client: HAPClient, server: HAPServer) {
        this.client = client;
        this.server = server;

        this.identifierCache = new IdentifierCache(this.client.clientInfo.clientId); // TODO load from disk

        this.addServiceFilter(new ProtocolInformationServiceFilter(this));
        // TODO this.addServiceFilter(new DataStreamTransportManagementServiceFilter(this));

        this.server.on(HAPServerEvents.ACCESSORIES, this.handleServerAccessories.bind(this));
        this.server.on(HAPServerEvents.GET_CHARACTERISTICS, this.handleServerGetCharacteristics.bind(this));
        this.server.on(HAPServerEvents.SET_CHARACTERISTICS, this.handleServerSetCharacteristics.bind(this));
        this.server.on(HAPServerEvents.PREPARE_WRITE, this.handleServerPrepareWrite.bind(this));
        this.server.on(HAPServerEvents.RESOURCE, this.handleServerResource.bind(this));

        this.client.on(HAPClientEvents.EVENT_RAW, this.handleAccessoryEvent.bind(this));
    }

    addServiceFilter(filter: ServiceFilter) {
        this.serviceFilters[filter.serviceType] = filter;
    }

    private getCharacteristicFilter(serviceType: string, characteristicType: string): CharacteristicFilter<any> | undefined {
        const serviceFilter = this.serviceFilters[serviceType];
        if (!serviceFilter) {
            return undefined;
        }

        return serviceFilter.characteristicsFilters[characteristicType];
    }

    private handleAccessoryEvent(eventBuf: Buffer) {
        console.log("Received event which needs to be forwarded!");
        // TODO track what connections are subscribed to which characteristics events
    }

    private handleServerAccessories(connection: HAPServerConnection, callback: HTTPServerResponseCallback) {
        this.client.accessories()
            .then(response => {
                // TODO check for errors

                this.identifierCache.rebuild(); // clear cache before we rebuild it

                const attributeDatabase: AttributeDatabase = JSON.parse(response.body.toString());
                console.log(attributeDatabase); // TODO remove

                attributeDatabase.accessories.forEach(accessory => {
                    // TODO support bridged accessories
                    if (accessory.aid !== 1) { // find primary accessory
                        return;
                    }

                    accessory.services.forEach(service => {
                        service.characteristics.forEach(characteristic => {
                            // TODO support shortened uuids (type)
                            this.identifierCache.persists(accessory.aid, characteristic.iid, service.type, characteristic.type);

                            if (characteristic.value) { // only need to filter if we actually return a value
                                // TODO instantiate new filter object for every occurence of this service type
                                const filter = this.getCharacteristicFilter(service.type, characteristic.type);
                                if (filter) {
                                    console.log("found characteristic filter"); // TODO remove

                                    characteristic.value = filter.filterRead(connection, characteristic.value);
                                }
                            }
                        });
                    });
                });

                response.body = Buffer.from(JSON.stringify(attributeDatabase));

                return this.identifierCache.save() // save newly built cache
                    .then(() => callback(undefined, HAPProxy.responseToServerResponse(response)));
            })
            .catch(reason => callback(new Error(reason)));
    }

    private handleServerGetCharacteristics(connection: HAPServerConnection, ids: ParsedUrlQuery, callback: HTTPServerResponseCallback) {
        this.client.getCharacteristicsRaw(ids)
            .then(response => {
                // TODO check for errors
                let rebuildResponse = false;
                const getResponse: CharacteristicsSetResponse = JSON.parse(response.body.toString());
                console.log(getResponse); // TODO remove

                getResponse.characteristics.forEach(characteristic => {
                    const identifiers = this.identifierCache.lookup(characteristic.aid, characteristic.iid);
                    if (!identifiers) {
                        console.log("Found uncached identifiers !!!!!"); // TODO remove
                        return;
                    }

                    const filter = this.getCharacteristicFilter(identifiers.serviceType, identifiers.characteristicType);
                    if (filter) {
                        const previousValue = characteristic.value;
                        characteristic.value = filter.filterRead(connection, characteristic.value);

                        if (previousValue !== characteristic.value) {
                            rebuildResponse = true;
                        }
                    }
                });

                if (rebuildResponse) {
                    response.body = Buffer.from(JSON.stringify(getResponse));
                }
                callback(undefined, HAPProxy.responseToServerResponse(response));
            })
            .catch(reason => callback(new Error(reason)));
    }

    private handleServerSetCharacteristics(connection: HAPServerConnection, writeRequest: Buffer, callback: HTTPServerResponseCallback) {
        let rebuildRequest = false;
        let containsWriteResponse = false;

        const request: CharacteristicsSetRequest = JSON.parse(writeRequest.toString());

        request.characteristics.forEach(characteristic => {
            if (characteristic.value) {
                const identifiers = this.identifierCache.lookup(characteristic.aid, characteristic.iid);
                if (!identifiers) {
                    console.log("Found uncached identifiers !!!!!"); // TODO remove
                    return;
                }

                const filter = this.getCharacteristicFilter(identifiers.serviceType, identifiers.characteristicType);
                if (filter) {
                    const previousValue = characteristic.value;
                    characteristic.value = filter.filterWrite(connection, characteristic.value);

                    if (previousValue !== characteristic.value) {
                        rebuildRequest = true;
                    }
                }
            }

            if (characteristic.ev !== undefined) {
                // TODO track event subscriptions
                // TODO track disconnection to unsubscribe from events (1:1 matching of connections)
            }

            if (characteristic.r) {
                containsWriteResponse = true;
            }
        });

        if (rebuildRequest) {
            writeRequest = Buffer.from(JSON.stringify(request));
        }

        this.client.setCharacteristicsRaw(writeRequest)
            .then(response => {
                if (containsWriteResponse) { // only decode response if we actually queried an control point characteristic
                    // TODO filter write response
                }

                callback(undefined, HAPProxy.responseToServerResponse(response));
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
