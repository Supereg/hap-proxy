export enum TLVValues {
    // noinspection JSUnusedGlobalSymbols
    METHOD = 0x00,
    IDENTIFIER = 0x01,
    SALT = 0x02,
    PUBLIC_KEY = 0x03,
    PASSWORD_PROOF = 0x04,
    ENCRYPTED_DATA = 0x05,
    STATE = 0x06,
    ERROR = 0x07,
    RETRY_DELAY = 0x08,
    CERTIFICATE = 0x09, // x.509 certificate
    SIGNATURE = 0x0A,  // ed25519
    PERMISSIONS = 0x0B, // None (0x00): regular user, 0x01: Admin (able to add/remove/list pairings)
    FRAGMENT_DATA = 0x0C,
    FRAGMENT_LAST = 0x0D,
    PAIRING_FLAGS = 0x13, // pairing flags
    SEPARATOR = 0x0FF // Zero-length TLV that separates different TLVs in a list.
}

// noinspection JSUnusedGlobalSymbols
export enum PairingFlags {
    // noinspection JSUnusedGlobalSymbols
    TRANSIENT_PAIR_SETUP = 0x10,
    SPLIT_PAIR_SETUP = 0x1000000,
}

export enum PairMethods {
    // noinspection JSUnusedGlobalSymbols
    PAIR_SETUP = 0x00,
    PAIR_SETUP_WITH_AUTH = 0x01,
    PAIR_VERIFY = 0x02,
    ADD_PAIRING = 0x03,
    REMOVE_PAIRING = 0x04,
    LIST_PAIRINGS = 0x05
}

export enum HAPStates {
    M1 = 0x01,
    M2 = 0x02,
    M3 = 0x03,
    M4 = 0x04,
    M5 = 0x05,
    M6 = 0x06
}

// Error codes and the like, guessed by packet inspection
export enum TLVErrors {
    // noinspection JSUnusedGlobalSymbols
    UNKNOWN = 0x01,
    INVALID_REQUEST = 0x02,
    AUTHENTICATION = 0x02, // setup code or signature verification failed
    BACKOFF = 0x03, // // client must look at retry delay tlv item
    MAX_PEERS = 0x04, // server cannot accept any more pairings
    MAX_TRIES = 0x05, // server reached maximum number of authentication attempts
    UNAVAILABLE = 0x06, // server pairing method is unavailable
    BUSY = 0x07 // cannot accept pairing request at this time
}

// noinspection JSUnusedGlobalSymbols
export enum HAPStatusCode { // body includes it if http status code is 4xx or 5xx
    // noinspection JSUnusedGlobalSymbols
    SUCCESS = 0,
    INSUFFICIENT_PRIVILEGES = -70401,
    SERVICE_COMMUNICATION_FAILURE = -70402,
    RESOURCE_BUSY = -70403,
    READ_ONLY_CHARACTERISTIC = -70404,
    WRITE_ONLY_CHARACTERISTIC = -70405,
    NOTIFICATION_NOT_SUPPORTED = -70406,
    OUT_OF_RESOURCE = -70407,
    OPERATION_TIMED_OUT = -70408,
    RESOURCE_DOES_NOT_EXIST = -70409,
    INVALID_VALUE_IN_REQUEST = -70410,
    INSUFFICIENT_AUTHORIZATION = -70411
}

export enum HAPAccessoryCategory {
    // noinspection JSUnusedGlobalSymbols
    OTHER = 1,
    BRIDGE = 2,
    FAN = 3,
    GARAGE_DOOR_OPENER = 4,
    LIGHTBULB = 5,
    DOOR_LOCK = 6,
    OUTLET = 7,
    SWITCH = 8,
    THERMOSTAT = 9,
    SENSOR = 10,
    ALARM_SYSTEM = 11,
    SECURITY_SYSTEM = 11, //Added to conform to HAP naming
    DOOR = 12,
    WINDOW = 13,
    WINDOW_COVERING = 14,
    PROGRAMMABLE_SWITCH = 15,
    RANGE_EXTENDER = 16,
    CAMERA = 17,
    IP_CAMERA = 17, //Added to conform to HAP naming
    VIDEO_DOORBELL = 18,
    AIR_PURIFIER = 19,
    AIR_HEATER = 20, //Not in HAP Spec
    AIR_CONDITIONER = 21, //Not in HAP Spec
    AIR_HUMIDIFIER = 22, //Not in HAP Spec
    AIR_DEHUMIDIFIER = 23, // Not in HAP Spec
    APPLE_TV = 24,
    HOMEPOD = 25, // HomePod
    SPEAKER = 26,
    AIRPORT = 27,
    SPRINKLER = 28,
    FAUCET = 29,
    SHOWER_HEAD = 30,
    TELEVISION = 31,
    TARGET_CONTROLLER = 32, // Remote Control
    ROUTER = 33 // HomeKit enabled router
}

export enum PairingStatusFlags {
    // noinspection JSUnusedGlobalSymbols
    PAIRED = 0x01,
    NOT_JOINED_WIFI = 0x02,
    PROBLEM = 0x04,
}

export class HAPEncryptionContext {

    sharedSecret: Buffer;

    encryptionKey: Buffer;
    encryptionNonce: number = 0;
    decryptionKey: Buffer;
    decryptionNonce: number = 0;
    frameBuffer?: Buffer; // used to store incomplete frames

    constructor(sharedSecret: Buffer, encryptionKey: Buffer, decryptionKey: Buffer) {
        this.sharedSecret = sharedSecret;
        this.encryptionKey = encryptionKey;
        this.decryptionKey = decryptionKey;
    }

}

export interface CharacteristicAttributeDatabase<T> {
    iid: number,
    type: string,
    value: T,
    perms: string[],
    format: string,
    description?: string,
}

export interface ServiceAttributeDatabase {
    iid: number,
    type: string,
    characteristics: CharacteristicAttributeDatabase<any>[],
}

export interface AccessoryAttributeDatabase {
    aid: number,
    services: ServiceAttributeDatabase[],
}

export interface AttributeDatabase {
    accessories: AccessoryAttributeDatabase[],
}

export interface CharacteristicsWriteRequest {
    characteristics: CharacteristicWriteRequest[],
    pid?: number,
}

export interface CharacteristicsWriteResponse {
    characteristics: CharacteristicWriteResponse[],
}

export interface CharacteristicsReadResponse {
    characteristics: CharacteristicReadResponse[],
}


export interface Characteristic {
    aid: number,
    iid: number,
}

export interface CharacteristicReadRequest extends Characteristic {}

export interface CharacteristicReadResponse extends Characteristic {
    value: any,
}

export interface CharacteristicWriteRequest extends Characteristic {
    value?: any,
    ev?: boolean,
    authData?: string,
    remote?: string,
    r?: string, // write response
}

export interface CharacteristicWriteResponse extends Characteristic {
    status: number,
    value?: any, // write response
}

export interface CharacteristicEventRequest extends Characteristic {
    ev: boolean,
}

export interface EventNotification {
    characteristics: CharacteristicReadResponse[],
}
