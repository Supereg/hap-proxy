import createDebug from "debug";
import {
    DataStreamServer,
    DataStreamServerConnection,
    DataStreamServerEvents,
    PreparedDataStreamSession
} from "./DataStreamServer";
import {DataStreamClient, DataStreamClientConnection} from "./DataStreamClient";
import {HAPServerConnection} from "../HAPServer";
import {HAPClientConnection} from "../HAPClient";
import crypto from "crypto";
import {DataStreamConnection, DataStreamConnectionEventMap, DataStreamConnectionEvents} from "./DataStreamConnection";

const debug = createDebug('DataStream:Proxy');

export class DataStreamProxy {

    private dataStreamServer: DataStreamServer = new DataStreamServer();
    private dataStreamClient: DataStreamClient = new DataStreamClient();

    constructor() {
        this.dataStreamServer.on(DataStreamServerEvents.CONNECTION_IDENTIFIED, this.handleConnectionIdentified.bind(this));
    }

    generateKeySalt(): Buffer {
        return crypto.randomBytes(16);
    }

    setupClient(hapConnection: HAPClientConnection, host: string, listeningPort: number, salt: Buffer): Promise<DataStreamClientConnection> {
        const connection = this.dataStreamClient.newConnection(hapConnection, host, listeningPort, salt);
        return connection.ensureConnected().then(() => connection);
    }

    setupController(connection: HAPServerConnection, controllerKeySalt: Buffer, clientConnection: DataStreamClientConnection): Promise<PreparedDataStreamSession> {
        return new Promise<PreparedDataStreamSession>(resolve => {
            this.dataStreamServer.prepareSession(connection, controllerKeySalt, clientConnection, preparedSession => resolve(preparedSession));
        });
    }

    private handleConnectionIdentified(preparedSession: PreparedDataStreamSession, serverConnection: DataStreamServerConnection) {
        const clientConnection = preparedSession.hdsClientConnection;

        serverConnection.on(DataStreamConnectionEvents.PAYLOAD, DataStreamProxy.forwardPayload.bind(this, clientConnection));
        serverConnection.on(DataStreamConnectionEvents.CLOSED, DataStreamProxy.forwardClose.bind(this, clientConnection));

        clientConnection.on(DataStreamConnectionEvents.PAYLOAD, DataStreamProxy.forwardPayload.bind(this, serverConnection));
        clientConnection.on(DataStreamConnectionEvents.CLOSED, DataStreamProxy.forwardClose.bind(this, serverConnection));
    }

    private static forwardPayload(connection: DataStreamConnection<DataStreamConnectionEventMap>, payload: Buffer) {
        console.log("Forwarding payload");
        connection.sendRawHDSFrame(payload);
    }

    private static forwardClose(connection: DataStreamConnection<DataStreamConnectionEventMap>) {
        console.log("Forwarding close");
        connection.close();
    }

}
