import {DataStreamServerConnection} from "./DataStreamServer";

export * from './DataStreamServer';
export * from './DataStreamParser';

export type EventHandler = (message: Record<any, any>) => void;
export type RequestHandler = (id: number, message: Record<any, any>) => void;
export type ResponseHandler = (error: Error | undefined, status: number | undefined, message: Record<any, any>) => void;
export type GlobalEventHandler = (connection: DataStreamServerConnection, message: Record<any, any>) => void;
export type GlobalRequestHandler = (connection: DataStreamServerConnection, id: number, message: Record<any, any>) => void;

export interface DataStreamProtocolHandler {

    eventHandler?: Record<string, EventHandler>,
    requestHandler?: Record<string, RequestHandler>,

}

export namespace DataStream {
    export const VERSION = "1.0";
}

export enum Protocols { // a collection of currently known protocols
    // noinspection JSUnusedGlobalSymbols
    CONTROL = "control",
    TARGET_CONTROL = "targetControl",
    DATA_SEND = "dataSend",
}

export enum Topics { // a collection of currently known topics grouped by their protocol
    // control
    // noinspection JSUnusedGlobalSymbols
    HELLO = "hello",

    // targetControl
    WHOAMI = "whoami",

    // dataSend
    OPEN = "open",
    DATA = "data",
    ACK = "ack",
    CLOSE = "close",
}

// noinspection JSUnusedGlobalSymbols
export enum DataSendCloseReason {
    // noinspection JSUnusedGlobalSymbols
    NORMAL = 0,
    NOT_ALLOWED = 1,
    BUSY = 2,
    CANCELLED = 3,
    UNSUPPORTED = 4,
    UNEXPECTED_FAILURE = 5,
    TIMEOUT = 6,
}

export type HDSFrame = {

    header: Buffer,
    cipheredPayload: Buffer,
    plaintextPayload: Buffer,
    authTag: Buffer,

}

export enum MessageType {
    EVENT = 1,
    REQUEST = 2,
    RESPONSE = 3,
}

export type DataStreamMessage = {
    type: MessageType,

    protocol: string,
    topic: string,
    id?: number, // for requests and responses
    status?: number, // for responses

    message: Record<any, any>,
}

export enum TransferTransportConfigurationTypes {
    TRANSFER_TRANSPORT_CONFIGURATION = 1,
}

export enum TransportTypeTypes {
    TRANSPORT_TYPE = 1,
}


export enum SetupDataStreamSessionTypes {
    SESSION_COMMAND_TYPE = 1,
    TRANSPORT_TYPE = 2,
    CONTROLLER_KEY_SALT = 3,
}

export enum SetupDataStreamWriteResponseTypes {
    STATUS = 1,
    TRANSPORT_TYPE_SESSION_PARAMETERS = 2,
    ACCESSORY_KEY_SALT = 3,
}

export enum TransportSessionConfiguration {
    TCP_LISTENING_PORT = 1,
}


export enum TransportType {
    HOMEKIT_DATA_STREAM = 0,
}

export enum SessionCommandType {
    START_SESSION = 0,
}

export enum DataStreamStatus {
    SUCCESS = 0,
    GENERIC_ERROR = 1,
    BUSY = 2, // maximum numbers of sessions
}
