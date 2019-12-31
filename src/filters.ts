import {CharacteristicFilterControlPoint, CharacteristicFilterR, ServiceFilter} from "./HAPProxy";
import {HAPServerConnection} from "./HAPServer";
import {CharacteristicType, ServiceType} from "./definitions";
import * as tlv from './utils/tlv';
import {DataStreamServer} from "./datastream";

/**
 * Service "Protocol Information"
 */

export class ProtocolInformationServiceNameCharacteristicFilter extends CharacteristicFilterR<string> {

    filterRead(connection: HAPServerConnection, readValue: string): string {
        return this.context.server.accessoryInfo.displayName; // override accessory name with the proxy server name
    }

}

export class ProtocolInformationServiceFilter extends ServiceFilter {

    serviceType: ServiceType = ServiceType.PROTOCOL_INFORMATION;

    init(): void {
        this.characteristicsFilters[CharacteristicType.NAME] = new ProtocolInformationServiceNameCharacteristicFilter(this.context);
    }

}

// TODO hap version service (=> warning on incompatible version)

/**
 * Service "DataStreamManagement"
 */

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

export class DataStreamTransportManagementServiceSetupDataStreamTransportCharacteristicFilter extends CharacteristicFilterControlPoint<string> {

    private dataStreamServer: DataStreamServer = new DataStreamServer();

    private lastSetupDataStreamTransportResponse: string = "";

    filterRead(connection: HAPServerConnection, readValue: string): string {
        return this.lastSetupDataStreamTransportResponse;
    }

    // TODO track access to the DataStreamManagementService
    filterWrite(connection: HAPServerConnection, writtenValue: string): string {
        const data = Buffer.from(writtenValue, "base64");
        const objects = tlv.decode(data);

        const sessionCommandType = objects[SetupDataStreamSessionTypes.SESSION_COMMAND_TYPE].readUInt8(0);
        const transportType = objects[SetupDataStreamSessionTypes.TRANSPORT_TYPE].readUInt8(0);
        const controllerKeySalt = objects[SetupDataStreamSessionTypes.CONTROLLER_KEY_SALT];

        // debug("Received setup write with command %s and transport type %s", SessionCommandType[sessionCommandType], TransportType[transportType]);

        if (sessionCommandType === SessionCommandType.START_SESSION) {
            if (transportType !== TransportType.HOMEKIT_DATA_STREAM) {
                return writtenValue;
            }

            /*
            this.dataStreamServer.prepareSession(connection, controllerKeySalt, preparedSession => {
                const listeningPort = tlv.encode(TransportSessionConfiguration.TCP_LISTENING_PORT, tlv.writeUInt16(preparedSession.port!));

                let response: Buffer = Buffer.concat([
                    tlv.encode(SetupDataStreamWriteResponseTypes.STATUS, DataStreamStatus.SUCCESS),
                    tlv.encode(SetupDataStreamWriteResponseTypes.TRANSPORT_TYPE_SESSION_PARAMETERS, listeningPort)
                ]);
                this.lastSetupDataStreamTransportResponse = response.toString('base64'); // save last response without accessory key salt

                response = Buffer.concat([
                    response,
                    tlv.encode(SetupDataStreamWriteResponseTypes.ACCESSORY_KEY_SALT, preparedSession.accessoryKeySalt)
                ]);
                callback(null, response.toString('base64'));
            });
            */

            // TODO build request
            return "";
        } else {
            return writtenValue;
        }
    }

    filterWriteResponse(connection: HAPServerConnection, writeResponseValue: string): string {
        return writeResponseValue;
    }

}

export class DataStreamTransportManagementServiceVersionCharacteristic extends CharacteristicFilterR<string> {

    filterRead(connection: HAPServerConnection, readValue: string): string {
        // TODO check supported version
        return readValue;
    }

}

export class DataStreamTransportManagementServiceFilter extends ServiceFilter {

    // TODO proxy data stream management traffic
    serviceType: ServiceType = ServiceType.DATA_STREAM_TRANSPORT_MANAGEMENT;

    init(): void {
        this.characteristicsFilters[CharacteristicType.SETUP_DATA_STREAM_MANAGEMENT] = new DataStreamTransportManagementServiceSetupDataStreamTransportCharacteristicFilter(this.context);
        this.characteristicsFilters[CharacteristicType.VERSION] = new DataStreamTransportManagementServiceVersionCharacteristic(this.context);
    }

}


// TODO support RTP proxy (?)
