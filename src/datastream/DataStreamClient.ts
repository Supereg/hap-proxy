import createDebug from "debug";
import net, {Socket} from "net";
import * as encryption from "../crypto/encryption"
import {HAPClientConnection, HAPClientConnectionEvents} from "../HAPClient";
import {DataStreamConnection, DataStreamConnectionEventMap, DataStreamConnectionEvents} from "./DataStreamConnection";

const debug = createDebug('DataStream:Client');

export class DataStreamClient {

    private connections: DataStreamClientConnection[] = [];

    newConnection(clientConnection: HAPClientConnection, host: string, port: number, salt: Buffer) {
        const accessoryToControllerInfo = Buffer.from("HDS-Read-Encryption-Key");
        const controllerToAccessoryInfo = Buffer.from("HDS-Write-Encryption-Key");

        const accessoryToControllerEncryptionKey = encryption.HKDF("sha512", salt, clientConnection.encryptionContext!.sharedSecret!, accessoryToControllerInfo, 32);
        const controllerToAccessoryEncryptionKey = encryption.HKDF("sha512", salt, clientConnection.encryptionContext!.sharedSecret!, controllerToAccessoryInfo, 32);

        const socket = net.createConnection(port, host);
        const connection = new DataStreamClientConnection(socket, clientConnection, controllerToAccessoryEncryptionKey, accessoryToControllerEncryptionKey);
        connection.on(DataStreamConnectionEvents.CLOSED, this.connectionClosed.bind(this, connection));

        this.connections.push(connection);

        return connection;
    }

    private connectionClosed(connection: DataStreamClientConnection) {
        debug("[%s] DataStream connection closed", connection.remoteAddress);

        const index = this.connections.indexOf(connection);
        if (index >= 0) {
            this.connections.splice(index, 1);
        }

        // TODO emit event(?)
    }

}

export enum DataStreamClientConnectionEvents {
    CONNECTED = "connect",
}

export interface DataStreamClientConnectionEventMap extends DataStreamConnectionEventMap {
    [DataStreamClientConnectionEvents.CONNECTED]: () => void;
}

export class DataStreamClientConnection extends DataStreamConnection<DataStreamClientConnectionEventMap> {

    private connection: HAPClientConnection;

    private connectPromise?: Promise<void>;
    private socketConnectResolve?: (value?: void | PromiseLike<void>) => void;
    private socketConnectReject?: (reason?: any) => void;

    constructor(socket: Socket, connection: HAPClientConnection, encryptionKey: Buffer, decryptionKey: Buffer) {
        super(socket);
        this.connection = connection;

        this.socket.on('connect', this.handleConnected.bind(this));
        this.connection.on(HAPClientConnectionEvents.DISCONNECTED, this.onHAPSessionClosed.bind(this)); // register close listener

        this.setKeys(encryptionKey, decryptionKey);
    }

    ensureConnected(): Promise<void> {
        if (this.connected) {
            return Promise.resolve();
        } else if (this.connectPromise) {
            return this.connectPromise;
        }

        return this.connectPromise = new Promise<void>((resolve, reject) => {
            this.socketConnectResolve = resolve;
            this.socketConnectReject = reject;
        });
    }

    private handleConnected() {
        this.remoteAddress = this.socket.remoteAddress!;
        this.connected = true;

        console.log("HDS Client is now connected"); // TODO adjust
        if (this.socketConnectResolve) {
            this.socketConnectResolve();

            this.socketConnectResolve = undefined;
            this.socketConnectReject = undefined;
        }

        this.emit(DataStreamClientConnectionEvents.CONNECTED);
        // TODO flush buffer queue
    }


    protected handleError(error: Error) {
        super.handleError(error);

        if (this.socketConnectReject) {
            this.socketConnectReject();

            this.socketConnectResolve = undefined;
            this.socketConnectReject = undefined;
        }
    }
}
