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
import {DataStreamMessage} from "./index";
import * as fs from "fs";

const debug = createDebug('DataStream:Proxy');

export class DataStreamProxy {

    private dataStreamServer: DataStreamServer = new DataStreamServer();
    private dataStreamClient: DataStreamClient = new DataStreamClient();

    constructor() {
        this.dataStreamServer.on(DataStreamServerEvents.CONNECTION_IDENTIFIED, this.handleConnectionIdentified.bind(this));
    }

    generateKeySalt(): Buffer {
        return crypto.randomBytes(32);
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
        serverConnection.on(DataStreamConnectionEvents.MESSAGE, (message: DataStreamMessage) => {
            console.log("Controller > Accessory: " + message.protocol + " " + message.topic);
            fs.appendFileSync("hds-communication.txt", "Controller > Accessory: " + DataStreamProxy.stringify(message));
        });
        serverConnection.on(DataStreamConnectionEvents.CLOSED, DataStreamProxy.forwardClose.bind(this, clientConnection));

        clientConnection.on(DataStreamConnectionEvents.PAYLOAD, DataStreamProxy.forwardPayload.bind(this, serverConnection));
        clientConnection.on(DataStreamConnectionEvents.MESSAGE, (message: DataStreamMessage) => {
            console.log("Accessory > Controller: " + message.protocol + " " + message.topic);
            fs.appendFileSync("hds-communication.txt", "Accessory > Controller: " + DataStreamProxy.stringify(message));
        });
        clientConnection.on(DataStreamConnectionEvents.CLOSED, DataStreamProxy.forwardClose.bind(this, serverConnection));
    }

    private static stringify(value: any) {
        return JSON.stringify(value, (_, v) => {
            if (typeof v === 'bigint') {
                return v.toString();
            } else if (typeof v === "object" && v.type === "Buffer") {
                const data = v.data;
                return Buffer.from(data).toString("hex");
            } else {
                return v;
            }
        }, 4);
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
