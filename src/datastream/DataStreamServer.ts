import createDebug from 'debug';
import assert from 'assert';
import * as hkdf from '../crypto/hkdf';
import crypto from 'crypto';
import net, {Socket} from 'net';
import {EventEmitter as NodeEventEmitter} from "events";
import {EventEmitter} from "../lib/EventEmitter";
import {HAPServerConnection, HAPServerConnectionEvents} from "../HAPServer";
import {
    DataStreamMessage,
    GlobalEventHandler,
    GlobalRequestHandler,
    HDSFrame,
    MessageType,
    Protocols,
    Topics
} from "./index";
import {
    ConnectionState,
    DataStreamConnection,
    DataStreamConnectionEventMap,
    DataStreamConnectionEvents
} from "./DataStreamConnection";
import Timeout = NodeJS.Timeout;
import {DataStreamClientConnection} from "./DataStreamClient";

const debug = createDebug('DataStream:Server');

export type PreparedDataStreamSession = {

    connection: HAPServerConnection, // reference to the hap session which created the request
    hdsClientConnection: DataStreamClientConnection, // reference to the proxied hds client // TODO a bit ugly regarding the abstraction level

    accessoryToControllerEncryptionKey: Buffer,
    controllerToAccessoryEncryptionKey: Buffer,
    accessoryKeySalt: Buffer,

    port?: number,

    connectTimeout?: Timeout, // 10s timer

}

enum ServerState {
    UNINITIALIZED, // server socket hasn't been created
    BINDING, // server is created and is currently trying to bind
    LISTENING, // server is created and currently listening for new connections
    CLOSING,
}

export enum DataStreamServerEvents {
    CONNECTION_OPENED = "connection-opened",
    CONNECTION_IDENTIFIED = "connection-identified",
    CONNECTION_CLOSED = "connection-closed",
}

export type DataStreamServerEventMap = {
    [DataStreamServerEvents.CONNECTION_OPENED]: (connection: DataStreamServerConnection) => void;
    [DataStreamServerEvents.CONNECTION_IDENTIFIED]: (preparedSession: PreparedDataStreamSession, connection: DataStreamServerConnection) => void;
    [DataStreamServerEvents.CONNECTION_CLOSED]: (connection: DataStreamServerConnection) => void;
}

/**
 * DataStreamServer which listens for incoming tcp connections and handles identification of new connections
 *
 * @event 'connection-opened': (connection: DataStreamServerConnection) => void
 *        This event is emitted when a new client socket is received. At this point we have no idea to what
 *        hap session this connection will be matched.
 *
 * @event 'connection-closed': (connection: DataStreamServerConnection) => void
 *        This event is emitted when the socket of a connection gets closed.
 */
export class DataStreamServer extends EventEmitter<DataStreamServerEventMap> {

    private state: ServerState = ServerState.UNINITIALIZED;

    private tcpServer?: net.Server;
    private tcpPort?: number;

    preparedSessions: PreparedDataStreamSession[];
    private connections: DataStreamServerConnection[];

    constructor() {
        super();
        this.preparedSessions = [];
        this.connections = [];
    }

    prepareSession(connection: HAPServerConnection, controllerKeySalt: Buffer, clientConnection: DataStreamClientConnection, callback: (preparedSession: PreparedDataStreamSession) => void) {
        debug("Preparing for incoming HDS connection from session %s", connection.sessionID);
        const accessoryKeySalt = crypto.randomBytes(32);
        const salt = Buffer.concat([controllerKeySalt, accessoryKeySalt]);

        const accessoryToControllerInfo = Buffer.from("HDS-Read-Encryption-Key");
        const controllerToAccessoryInfo = Buffer.from("HDS-Write-Encryption-Key");

        const accessoryToControllerEncryptionKey = hkdf.HKDF("sha512", salt, connection.encryptionContext!.sharedSecret!, accessoryToControllerInfo, 32);
        const controllerToAccessoryEncryptionKey = hkdf.HKDF("sha512", salt, connection.encryptionContext!.sharedSecret!, controllerToAccessoryInfo, 32);

        const preparedSession: PreparedDataStreamSession = {
            connection: connection,
            hdsClientConnection: clientConnection,
            accessoryToControllerEncryptionKey: accessoryToControllerEncryptionKey,
            controllerToAccessoryEncryptionKey: controllerToAccessoryEncryptionKey,
            accessoryKeySalt: accessoryKeySalt,
            connectTimeout: setTimeout(() => this.timeoutPreparedSession(preparedSession), 10000),
        };
        this.preparedSessions.push(preparedSession);

        this.checkTCPServerEstablished(preparedSession, () => callback(preparedSession));
    }

    private timeoutPreparedSession(preparedSession: PreparedDataStreamSession) {
        debug("Prepared HDS session timed out out since no connection was opened for 10 seconds (%s)", preparedSession.connection.sessionID);
        const index = this.preparedSessions.indexOf(preparedSession);
        if (index >= 0) {
            this.preparedSessions.splice(index, 1);
        }

        this.checkCloseable();
    }

    private checkTCPServerEstablished(preparedSession: PreparedDataStreamSession, callback: () => void) {
        switch (this.state) {
            case ServerState.UNINITIALIZED:
                debug("Starting up TCP server.");
                this.tcpServer = net.createServer();

                this.tcpServer.once('listening', this.listening.bind(this, preparedSession, callback));
                this.tcpServer.on('connection', this.onConnection.bind(this));
                this.tcpServer.on('close', this.closed.bind(this));

                this.tcpServer.listen();
                this.state = ServerState.BINDING;
                break;
            case ServerState.BINDING:
                debug("TCP server already running. Waiting for it to bind.");
                this.tcpServer!.once('listening', this.listening.bind(this, preparedSession, callback));
                break;
            case ServerState.LISTENING:
                debug("Instructing client to connect to already running TCP server");
                preparedSession.port = this.tcpPort;
                callback();
                break;
            case ServerState.CLOSING:
                debug("TCP socket is currently closing. Trying again when server is fully closed and opening a new one then.");
                this.tcpServer!.once('close', () => setTimeout(() => this.checkTCPServerEstablished(preparedSession, callback), 10));
                break;
        }
    }

    private listening(preparedSession: PreparedDataStreamSession, callback: () => void) {
        this.state = ServerState.LISTENING;

        const address = this.tcpServer!.address();
        if (address && typeof address !== "string") { // address is only typeof string when listening to a pipe or unix socket
            this.tcpPort = address.port;
            preparedSession.port = address.port;

            debug("TCP server is now listening for new data stream connections on port %s", address.port);
            callback();
        }
    }

    private onConnection(socket: Socket) {
        debug("[%s] New DataStream connection was established", socket.remoteAddress);
        const connection = new DataStreamServerConnection(socket);

        connection.on(DataStreamServerConnectionEvents.IDENTIFICATION, this.handleSessionIdentification.bind(this, connection));
        connection.on(DataStreamConnectionEvents.CLOSED, this.connectionClosed.bind(this, connection));

        this.connections.push(connection);

        this.emit(DataStreamServerEvents.CONNECTION_OPENED, connection);
    }

    private handleSessionIdentification(connection: DataStreamServerConnection, firstFrame: HDSFrame, callback: IdentificationCallback) {
        let identifiedSession: PreparedDataStreamSession | undefined = undefined;
        for (let i = 0; i < this.preparedSessions.length; i++) {
            const preparedSession = this.preparedSessions[i];

            // if we successfully decrypt the first frame with this key we know to which session this connection belongs
            if (connection.decryptHDSFrame(firstFrame, preparedSession.controllerToAccessoryEncryptionKey)) {
                identifiedSession = preparedSession;
                break;
            }
        }

        callback(identifiedSession);

        if (identifiedSession) {
            debug("[%s] Connection was successfully identified (linked with sessionId: %s)", connection.remoteAddress, identifiedSession.connection.sessionID);
            const index = this.preparedSessions.indexOf(identifiedSession);
            if (index >= 0) {
                this.preparedSessions.splice(index, 1);
            }

            clearTimeout(identifiedSession.connectTimeout!);
            identifiedSession.connectTimeout = undefined;

            this.emit(DataStreamServerEvents.CONNECTION_IDENTIFIED, identifiedSession, connection);
        } else {
            debug("[%s] Could not identify connection. Terminating.", connection.remoteAddress);
            connection.close(); // disconnecting since first message was not a valid hello
        }
    }

    private connectionClosed(connection: DataStreamServerConnection) {
        debug("[%s] DataStream connection closed", connection.remoteAddress);

        const index = this.connections.indexOf(connection);
        if (index >= 0) {
            this.connections.splice(index, 1);
        }

        this.emit(DataStreamServerEvents.CONNECTION_CLOSED, connection);

        this.checkCloseable();
    }

    private checkCloseable() {
        if (this.connections.length === 0 && this.preparedSessions.length === 0) {
            debug("Last connection disconnected. Closing the server now.");

            this.state = ServerState.CLOSING;
            // noinspection JSIgnoredPromiseFromCall
            this.tcpServer!.close();
        }
    }

    private closed() {
        this.tcpServer = undefined;
        this.tcpPort = undefined;

        this.state = ServerState.UNINITIALIZED;
    }

}

export enum DataStreamServerConnectionEvents {
    IDENTIFICATION = "identification",
}

export type IdentificationCallback = (identifiedSession?: PreparedDataStreamSession) => void;

export interface DataStreamServerConnectionEventMap extends DataStreamConnectionEventMap {
    [DataStreamServerConnectionEvents.IDENTIFICATION]: (frame: HDSFrame, callback: IdentificationCallback) => void;
}

/**
 * DataStream connection which holds any necessary state information, encryption an decryption keys, manages
 * protocol handlers and also handles sending and receiving of data stream frames.
 *
 * @event 'identification': (frame: HDSFrame, callback: IdentificationCallback) => void
 *        This event is emitted when the first HDSFrame is received from a new connection.
 *        The connection expects the handler to identify the connection by trying to match the decryption keys.
 *        If identification was successful the PreparedDataStreamSession should be supplied to the callback,
 *        otherwise undefined should be supplied.
 *
 * @event 'handle-message-globally': (message: DataStreamMessage) => void
 *        This event is emitted when no handler could be found for the given protocol of a event or request message.
 *
 * @event 'closed': () => void
 *        This event is emitted when the socket of the connection was closed.
 */
export class DataStreamServerConnection extends DataStreamConnection<DataStreamServerConnectionEventMap> {

    private connection?: HAPServerConnection; // reference to the hap session. is present when state > UNIDENTIFIED

    constructor(socket: Socket) {
        super(socket);
        this.remoteAddress = socket.remoteAddress!;
        this.connected = true;
    }


    protected handleInitialization(firstFrame: HDSFrame) {
        this.emit(DataStreamServerConnectionEvents.IDENTIFICATION, firstFrame, (identifiedSession?: PreparedDataStreamSession) => {
            if (identifiedSession) {
                // horray, we found our session
                this.connection = identifiedSession.connection;
                this.connection.on(HAPServerConnectionEvents.DISCONNECTED, this.onHAPSessionClosed.bind(this)); // register close listener

                this.setKeys(identifiedSession.accessoryToControllerEncryptionKey, identifiedSession.controllerToAccessoryEncryptionKey);
            }
        });
    }
}
