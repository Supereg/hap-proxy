import {ServiceFilter} from "./ServiceFilter";
import {HAPServerConnection} from "../HAPServer";
import {HAPProxy} from "../HAPProxy";
import {HAPClientConnection} from "../HAPClient";

/**
 * Read/write (with write response) characteristic filter
 */
export abstract class CharacteristicFilter<T> {

    readonly context: HAPProxy;
    readonly parent: ServiceFilter;
    readonly iid: number; // instance id of the characteristic

    /**
     * Creates a new instance of a CharacteristicFilter
     *
     * @param context {HAPProxy} - the associated proxy instance
     * @param parent {ServiceFilter} - the associated ServiceFilter instance
     * @param iid {number} - instance id of the characteristic
     */
    public constructor(context: HAPProxy, parent: ServiceFilter, iid: number) {
        this.context = context;
        this.parent = parent;
        this.iid = iid;
    }

    abstract filterRead(serverConnection: HAPServerConnection, clientConnection: HAPClientConnection, readValue: T): Promise<T>;

    abstract filterWrite(serverConnection: HAPServerConnection, clientConnection: HAPClientConnection, writtenValue: T): Promise<T>;

    abstract filterWriteResponse(serverConnection: HAPServerConnection, clientConnection: HAPClientConnection, writeResponseValue: T): Promise<T>;

}

/**
 * Read/write characteristic filter
 */
export abstract class CharacteristicFilterRW<T> extends CharacteristicFilter<T> {

    async filterWriteResponse(serverConnection: HAPServerConnection, clientConnection: HAPClientConnection, writeResponseValue: T): Promise<T> {
        return writeResponseValue;
    }

}

/**
 * Read only characteristic filter
 */
export abstract class CharacteristicFilterR<T> extends CharacteristicFilterRW<T> {

    async filterWrite(serverConnection: HAPServerConnection, clientConnection: HAPClientConnection, writtenValue: T): Promise<T> {
        return writtenValue; // its not allowed so just forward it. Client will return an error
    }

}

// noinspection JSUnusedGlobalSymbols
/**
 * Write only characteristic filter
 */
export abstract class CharacteristicFilterW<T> extends CharacteristicFilterRW<T> {

    async filterRead(serverConnection: HAPServerConnection, clientConnection: HAPClientConnection, readValue: T): Promise<T> {
        return readValue;
    }

}

/**
 * Control point characteristic filter
 */
export abstract class CharacteristicFilterControlPoint<T> extends CharacteristicFilter<T> {

    async filterRead(serverConnection: HAPServerConnection, clientConnection: HAPClientConnection, readValue: T): Promise<T> {
        return readValue;
    }

}

/**
 * Creates a new instance of a CharacteristicFilter
 *
 * @param context {HAPProxy} - the associated proxy instance
 * @param parent {ServiceFilter} - the associated ServiceFilter instance
 * @param iid {number} - instance id of the characteristic
 */
export type CharacteristicFilterConstructor<T> = new(context: HAPProxy, parent: ServiceFilter, iid: number) => CharacteristicFilter<T>;
