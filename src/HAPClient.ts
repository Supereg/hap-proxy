import net, {Socket} from 'net';
import createDebug from 'debug';
import assert from 'assert';
import * as tlv from './lib/utils/tlv';
import * as encryption from './lib/crypto/encryption';
import * as hkdf from './lib/crypto/hkdf';
import tweetnacl, {SignKeyPair} from 'tweetnacl';
import srp from 'fast-srp-hap';
import {HTTPResponse, HTTPResponseParser} from "./lib/http-protocol";
import {ClientInfo} from "./lib/ClientInfo";

const debug = createDebug("HAPClient");
const debugCon = createDebug("HAPClient:Connection");

export type PinProvider = (callback: (pinCode: string) => void) => void;

export class HAPClient {

    clientInfo: ClientInfo;

    connection?: HAPClientConnection;
    host: string;
    port: number;
    pinProvider: PinProvider;

    static async loadClient(clientId: string, host: string, port: number, pinProvider: PinProvider) {
        clientId = clientId.toUpperCase();
        debug("Loading clientInfo for '%s'", clientId);
        const clientInfo = await ClientInfo.loadOrCreate(clientId);

        return new HAPClient(clientInfo, host, port, pinProvider);
    }

    private constructor(clientInfo: ClientInfo, host: string, port: number, pinProvider: PinProvider) {
        this.clientInfo = clientInfo;
        this.host = host;
        this.port = port;
        this.pinProvider = pinProvider;
    }


    establishConnection() {
        this.connection = new HAPClientConnection(this);
    }

}

export enum HTTPMethod {
    GET = "GET",
    POST = "POST",
    PUT = "PUT",
}

export enum HTTPContentType {
    JSON = "application/json",
    PAIRING_TLV8 = "application/pairing+tlv8",
}

export enum HTTPRoutes {
    // noinspection JSUnusedGlobalSymbols
    IDENTIFY = '/identify',
    PAIR_SETUP = "/pair-setup",
    PAIR_VERIFY = "/pair-verify",
    PAIRINGS = "/pairings",
    ACCESSORIES = "/accessories",
    CHARACTERISTICS = "/characteristics",
    PREPARE = "/prepare",
    RESOURCE = "/resource",
}

export enum TLVValues {
    // noinspection JSUnusedGlobalSymbols
    METHOD = 0x00,
    IDENTIFIER = 0x01,
    SALT = 0x02,
    PUBLIC_KEY = 0x03,
    PROOF = 0x04,
    ENCRYPTED_DATA = 0x05,
    STATE = 0x06,
    ERROR_CODE = 0x07,
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

export enum States {
    M1 = 0x01,
    M2 = 0x02,
    M3 = 0x03,
    M4 = 0x04,
    M5 = 0x05,
    M6 = 0x06
}

// Error codes and the like, guessed by packet inspection
export enum ErrorCodes {
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
export enum HAPStatusCode {
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

export enum HTTPHeader {
    // noinspection JSUnusedGlobalSymbols
    CONTENT_TYPE = "Content-Type",
    DATE = "Date",
    CONNECTION = "Connection",
    TRANSFER_ENCODING = "Transfer-Encoding",
    CONTENT_LENGTH = "Content-Length",
}

export enum HTTPStatus {
    NO_CONTENT = 204,
}

export type PairSetupSession = {
    pinCode: string,
    srpClient: srp.Client,
    longTerm: SignKeyPair,
    encryptionKey: Buffer,
}

export type PairVerifySession = {

    // Curve25519KeyPair (M1)
    secretKey: Buffer;
    publicKey: Buffer;

    // M2
    sharedSecret: Buffer;
    encryptionKey: Buffer;
}

export type ResponseHandler = (response: HTTPResponse) => void;

export class HAPClientConnection {

    private socket: Socket;
    private parser: HTTPResponseParser;

    private readonly clientInfo: ClientInfo;
    private readonly host: string;
    private readonly port: number;
    private readonly pinProvider: PinProvider;

    private pairSetupSession?: Partial<PairSetupSession>;
    private pairVerifySession?: Partial<PairVerifySession>;

    private currentResponseHandler?: ResponseHandler;

    constructor(hapClient: HAPClient) {
        this.parser = new HTTPResponseParser();

        this.clientInfo = hapClient.clientInfo;
        this.host = hapClient.host;
        this.port = hapClient.port;
        this.pinProvider = hapClient.pinProvider;

        debugCon("Opening socket...");
        this.socket = net.createConnection(this.port, this.host);
        this.socket.on('connect', this.handleConnected.bind(this));
        this.socket.on('data', this.handleIncomingData.bind(this));

        this.socket.setKeepAlive(true);
        this.socket.setNoDelay(true);
    }

    handleConnected() {
        debugCon("Successfully connected!");

        if (this.clientInfo.paired) {
            this.sendPairVerifyM1();
        } else {
            this.pinProvider(pinCode => this.pair(pinCode))
        }
    }

    private abort() {
        this.pairVerifySession = undefined;
        this.pairSetupSession = undefined;
        this.socket.destroy();
    }

    pair(pin: string) {
        this.pairSetupSession = {
            pinCode: pin,
        };
        this.sendPairM1();
    }

    private sendPairM1() {
        debugCon("Sending pair setup M1");

        const startRequest = tlv.encode(
            TLVValues.STATE, States.M1,
            TLVValues.METHOD, PairMethods.PAIR_SETUP,
        );

        this.sendRequest(HTTPMethod.POST, HTTPRoutes.PAIR_SETUP, HTTPContentType.PAIRING_TLV8, this.handlePairM2.bind(this), startRequest);
    }

    private handlePairM2(response: HTTPResponse) {
        debugCon("Received pair setup M2 response");

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE][0];
        assert(state === States.M2, "Response was not in state M2");

        if (objects[TLVValues.ERROR_CODE]) {
            debugCon("M2: received error code " + ErrorCodes[objects[TLVValues.ERROR_CODE][0]]);
            this.abort();
            return;
        }

        const serverPublicKey = objects[TLVValues.PUBLIC_KEY];
        const salt = objects[TLVValues.SALT];
        this.sendPairM3(serverPublicKey, salt);
    }

    private sendPairM3(serverPublicKey: Buffer, salt: Buffer) {
        debugCon("Sending pair setup M3");

        const pin = this.pairSetupSession!.pinCode!;
        const srpParams = srp.params['3072'];
        srp.genKey(32, (err, key) => {
            const client = new srp.Client(srpParams, salt, Buffer.from("Pair-Setup"), Buffer.from(pin), key);
            this.pairSetupSession!.srpClient = client;

            client.setB(serverPublicKey);
            const A = client.computeA();
            const M1 = client.computeM1();

            const verifyRequest = tlv.encode(
                TLVValues.STATE, States.M3,
                TLVValues.PUBLIC_KEY, A,
                TLVValues.PROOF, M1,
            );

            this.sendRequest(HTTPMethod.POST, HTTPRoutes.PAIR_SETUP, HTTPContentType.PAIRING_TLV8, this.handlePairM4.bind(this), verifyRequest);
        })
    }

    private handlePairM4(response: HTTPResponse) {
        debugCon("Received pair setup M4 response");

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE][0];
        assert(state === States.M4, "Response was not in state M4");

        if (objects[TLVValues.ERROR_CODE]) {
            debugCon("M4: received error code " + ErrorCodes[objects[TLVValues.ERROR_CODE][0]]);
            this.abort();
            return;
        }

        const session = this.pairSetupSession!;
        const srpClient = session.srpClient!;

        const serverProof = objects[TLVValues.PROOF];
        const encryptedData = objects[TLVValues.ENCRYPTED_DATA];

        try {
            srpClient.checkM2(serverProof);
        } catch (error) {
            debugCon("ERROR: srp serverProof could not be verified: " + error.message);
            this.abort();
            return;
        }

        if (encryptedData) {
            debugCon("Received MFI challenge, ignoring it");
        }

        this.sendPairM5();
    }

    private sendPairM5() {
        debugCon("Sending pair setup M5");
        const session = this.pairSetupSession!;
        const srpClient = session.srpClient!;

        // step 1 (LT keys already generated)

        // step 2 derive iOSDeviceX
        let salt = Buffer.from("Pair-Setup-Controller-Sign-Salt");
        let info = Buffer.from("Pair-Setup-Controller-Sign-Info");
        const iOSDeviceX = hkdf.HKDF("sha512", salt, srpClient.computeK(), info, 32);

        // step 3
        const iOSDeviceInfo = Buffer.concat([
            iOSDeviceX,
            Buffer.from(this.clientInfo.clientId),
            this.clientInfo.longTermPublicKey,
        ]);

        // step 4
        const iOSDeviceSignature = tweetnacl.sign.detached(iOSDeviceInfo, this.clientInfo.longTermSecretKey);

        // step 5
        const subTLV = tlv.encode(
            TLVValues.IDENTIFIER, this.clientInfo.clientId,
            TLVValues.PUBLIC_KEY, this.clientInfo.longTermPublicKey,
            TLVValues.SIGNATURE, iOSDeviceSignature,
        );

        // step 6
        salt = Buffer.from("Pair-Setup-Encrypt-Salt");
        info = Buffer.from("Pair-Setup-Encrypt-Info");
        session.encryptionKey = hkdf.HKDF("sha512", salt, srpClient.computeK(), info, 32);

        const nonce = Buffer.from("PS-Msg05");
        const encryptedData = Buffer.alloc(subTLV.length);
        const authTag = Buffer.alloc(16);
        encryption.encryptAndSeal(session.encryptionKey, nonce, subTLV, null, encryptedData, authTag);

        // step 7
        const exchangeRequest = tlv.encode(
            TLVValues.STATE, States.M5,
            TLVValues.ENCRYPTED_DATA, Buffer.concat([encryptedData, authTag]),
        );
        this.sendRequest(HTTPMethod.POST, HTTPRoutes.PAIR_SETUP, HTTPContentType.PAIRING_TLV8, this.handlePairM6.bind(this), exchangeRequest);
    }

    private handlePairM6(response: HTTPResponse) {
        debugCon("Received pair setup M6 response");
        const session = this.pairSetupSession!;

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE][0];
        assert(state === States.M6, "Response was not in state M6");

        if (objects[TLVValues.ERROR_CODE]) {
            debugCon("M6: received error code " + ErrorCodes[objects[TLVValues.ERROR_CODE][0]]);
            this.abort();
            return;
        }

        // step 1 + 2
        const encryptedDataContent = objects[TLVValues.ENCRYPTED_DATA];
        const encryptedData = encryptedDataContent.slice(0, -16);
        const authTag = encryptedDataContent.slice(-16);

        const nonce = Buffer.from("PS-Msg06");
        const plaintextBuffer = Buffer.alloc(encryptedData.length);
        if (!encryption.verifyAndDecrypt(session.encryptionKey!, nonce, encryptedData, authTag, null, plaintextBuffer)) {
            debugCon("M6: Could not verify and decrypt!");
            this.abort();
            return;
        }

        const subTLV = tlv.decode(plaintextBuffer);
        const accessoryIdentifier = subTLV[TLVValues.IDENTIFIER];
        const accessoryLTPK = subTLV[TLVValues.PUBLIC_KEY];
        const accessorySignature = subTLV[TLVValues.SIGNATURE];

        // step 3
        const salt = Buffer.from("Pair-Setup-Accessory-Sign-Salt");
        const info = Buffer.from("Pair-Setup-Accessory-Sign-Info");
        const accessoryX = hkdf.HKDF("sha512", salt, session.srpClient!.computeK(), info, 32);

        const accessoryInfo = Buffer.concat([
            accessoryX,
            accessoryIdentifier,
            accessoryLTPK,
        ]);
        if (!tweetnacl.sign.detached.verify(accessoryInfo, accessorySignature, accessoryLTPK)) {
            debugCon("M6: Could not verify accessory signature!");
            this.abort();
            return;
        }

        this.clientInfo.accessoryIdentifier = accessoryIdentifier.toString();
        this.clientInfo.accessoryLTPK = accessoryLTPK;
        this.clientInfo.paired = true;

        this.pairSetupSession = undefined;

        debugCon("Successfully paired with %s", accessoryIdentifier.toString());

        this.clientInfo.save().then(() => this.sendPairVerifyM1());
    }

    private sendPairVerifyM1() {
        debugCon("Sending pair-verify M1");

        const keyPair = encryption.generateCurve25519KeyPair();
        const secretKey = Buffer.from(keyPair.secretKey);
        const publicKey = Buffer.from(keyPair.publicKey);

        this.pairVerifySession = {
            secretKey: secretKey,
            publicKey: publicKey,
        };

        const startRequest = tlv.encode(
            TLVValues.STATE, States.M1,
            TLVValues.PUBLIC_KEY, publicKey
        );

        this.sendRequest(HTTPMethod.POST, HTTPRoutes.PAIR_VERIFY, HTTPContentType.PAIRING_TLV8, this.handlePairVerifyM2.bind(this), startRequest);
    }

    private handlePairVerifyM2(response: HTTPResponse) {
        debugCon("Received pair-verify M2");

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE].readUInt8(0);
        const error = objects[TLVValues.ERROR_CODE];
        const serverPublicKey = objects[TLVValues.PUBLIC_KEY];
        const encryptedData = objects[TLVValues.ENCRYPTED_DATA];

        assert.strictEqual(state, States.M2, "PairVerify state did not match M2");

        if (error) {
            debugCon("Pair-Verify M2 returned with error: " + ErrorCodes[error[0]]);
            this.abort();
            return;
        }

        assert.strictEqual(serverPublicKey.length, 32, "serverPublicKey must be 32 bytes");

        const session = this.pairVerifySession!;

        // Step 1
        const sharedSecret = Buffer.from(
            encryption.generateCurve25519SharedSecKey(session.secretKey!, serverPublicKey)
        );

        // Step 2
        const encryptionSalt = Buffer.from("Pair-Verify-Encrypt-Salt");
        const encryptionInfo = Buffer.from("Pair-Verify-Encrypt-Info");
        const encryptionKey = hkdf.HKDF("sha512", encryptionSalt, sharedSecret, encryptionInfo, 32);

        session.sharedSecret = sharedSecret;
        session.encryptionKey = encryptionKey;

        // Step 3 & 4
        const cipherText = encryptedData.slice(0, -16);
        const authTag = encryptedData.slice(-16);
        const plaintext = Buffer.alloc(cipherText.length);

        const nonce = Buffer.from("PV-Msg02");
        if (!encryption.verifyAndDecrypt(encryptionKey, nonce, cipherText, authTag, null, plaintext)) {
            console.error("WARNING: M2 - Could not verify cipherText");
            this.abort();
            return;
        }

        // Step 5
        const data = tlv.decode(plaintext);
        const accessoryIdentifier = data[TLVValues.IDENTIFIER];
        const accessorySignature = data[TLVValues.SIGNATURE];

        // we would need to lookup our pairing (retrieve accessoryLTPK).
        // We do however only support one pairing, thus check if ids match
        if (this.clientInfo.accessoryIdentifier !== accessoryIdentifier.toString()) {
            console.error("WARNING: identifier is not the expected store in the keystore");
            this.abort();
            return;
        }

        // Step 6
        const accessoryInfo = Buffer.concat([
            serverPublicKey,
            accessoryIdentifier,
            session.publicKey!
        ]);

        if (!tweetnacl.sign.detached.verify(accessoryInfo, accessorySignature, this.clientInfo.accessoryLTPK)) {
            debugCon("M2: Failed in pair-verify to verify accessory signature!");
            this.abort();
            return;
        }

        this.sendPairVerifyM3(serverPublicKey, encryptionKey);
    }

    private sendPairVerifyM3(serverPublicKey: Buffer, encryptionKey: Buffer) {
        debugCon("Sending pair-verify M3");
        const session = this.pairVerifySession!;

        // Step 7
        const iOSDeviceInfo = Buffer.concat([
            session.publicKey!,
            Buffer.from(this.clientInfo.clientId),
            serverPublicKey,
        ]);

        // Step 8
        const iOSDeviceSignature = Buffer.from(tweetnacl.sign.detached(iOSDeviceInfo, this.clientInfo.longTermSecretKey));

        // Step 9
        const plainTextTLV = tlv.encode(
            TLVValues.IDENTIFIER, this.clientInfo.clientId,
            TLVValues.SIGNATURE, iOSDeviceSignature,
        );

        // Step 10
        const cipherText = Buffer.alloc(plainTextTLV.length);
        const authTag = Buffer.alloc(16);
        const nonce = Buffer.from("PV-Msg03");
        encryption.encryptAndSeal(encryptionKey, nonce, plainTextTLV, null, cipherText, authTag);

        // Step 11
        const finishRequest = tlv.encode(
            TLVValues.STATE, States.M3,
            TLVValues.ENCRYPTED_DATA, Buffer.concat([cipherText, authTag]),
        );

        // TODO save encryption keys

        // Step 12
        this.sendRequest(HTTPMethod.POST, HTTPRoutes.PAIR_VERIFY, HTTPContentType.PAIRING_TLV8, this.handlePairVerifyM4.bind(this), finishRequest);
    }

    private handlePairVerifyM4(response: HTTPResponse) {
        debugCon("Received pair-verify step M4");

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE].readUInt8(0);
        const error = objects[TLVValues.ERROR_CODE];

        assert.strictEqual(state, States.M4, "PairVerify state did not match M4");

        this.pairVerifySession = undefined;
        if (error) {
            debugCon("Pair-Verify was unsuccessful: " + ErrorCodes[error[0]]);
            this.abort();
        } else {
            debugCon("Pair-Verify was successful");
        }
        // TODO install encryption and decryption layers
    }

    handleIncomingData(data: Buffer) {
        this.parser.appendData(data);

        const messages: HTTPResponse[] = this.parser.parse();

        messages.forEach(message => {
            if (message.messageType === "EVENT") {
                console.log("RECEVIED EVENT");
            } else if (message.messageType === "HTTP") {
                if (this.currentResponseHandler) {
                    const handler = this.currentResponseHandler;
                    this.currentResponseHandler = undefined;
                    handler(message);
                } else {
                    console.error("WARNING: Received http response when not expecting anything!");
                }
            } else {
                console.error("WARNING: Received unknown message type!");
            }
        })
    }

    private sendRequest(method: HTTPMethod, route: HTTPRoutes, contentType: HTTPContentType, handler: ResponseHandler, data?: Buffer) {
        if (this.currentResponseHandler) {
            console.error("WARNING: http request still in progress");
            return;
        }
        // TODO pincode layer?

        const headers: Record<string, string> = {
            "Content-Type": contentType,
        };
        if (data && (method === HTTPMethod.POST || method === HTTPMethod.PUT)) {
            headers["Content-Length"] = data.length + "";
        } else {
            data = Buffer.alloc(0);
        }

        const request = Buffer.concat([
            Buffer.from(
                `${method} ${route} HTTP/1.1\r\n` +
                `Host: ${this.host}:${this.port}\r\n` +
                Object.keys(headers).reduce((acc: string, header: string) => {
                    return acc + `${header}: ${headers[header]}\r\n`;
                }, "") +
                `\r\n` // additional newline before content
            ),
            data
        ]);

        this.currentResponseHandler = handler;
        // TODO encryption layer
        this.socket.write(request);
    }

}
