import net, {Socket} from 'net';
import createDebug from 'debug';
import assert from 'assert';
import crypto from 'crypto';
import * as tlv from './utils/tlv';
import * as encryption from './crypto/encryption';
import tweetnacl from 'tweetnacl';
import {HTTPContentType, HTTPMethod, HTTPResponse, HTTPResponseParser, HTTPRoutes} from "./lib/http-protocol";
import {ClientInfo} from "./storage/ClientInfo";
import {EventEmitter} from "./lib/EventEmitter";
import {
    CharacteristicEventRequest,
    CharacteristicReadRequest,
    CharacteristicsWriteRequest,
    CharacteristicWriteRequest,
    HAPEncryptionContext,
    HAPStates,
    PairMethods,
    TLVErrors,
    TLVValues
} from "./types/hap-proxy";
import {ParsedUrlQuery} from "querystring";
import {BonjourBrowserEvents, HAPBonjourBrowser, HAPDeviceInfo} from "./lib/HAPBonjourBrowser";
import {SRP, SrpClient} from "fast-srp-hap";

const debug = createDebug("HAPClient");
const debugCon = createDebug("HAPClient:Connection");

export type PinProvider = (callback: (pinCode: string) => void) => void; // TODO move some more general

export type ClientPairSetupSession = {
    initiator: HAPClientConnection,

    srpClient: SrpClient,
    sharedSecret: Buffer,
    sessionKey: Buffer,
}

export type PairVerifySession = {

    // Curve25519KeyPair (M1)
    secretKey: Buffer;
    publicKey: Buffer;

    // M2
    sharedSecret: Buffer;
}

export enum HAPClientEvents {
    CONFIG_NUMBER_CHANGE = "config-number-change",
}

export type HAPClientEventMap = {
    [HAPClientEvents.CONFIG_NUMBER_CHANGE]: (configNumber: number) => void;
}

export class HAPClient extends EventEmitter<HAPClientEventMap> {

    clientInfo: ClientInfo;
    bonjourBrowser: HAPBonjourBrowser;

    deviceInfo?: HAPDeviceInfo;

    connections: HAPClientConnection[] = [];
    private pairSetupSession?: Partial<ClientPairSetupSession>;

    private currentChain: Promise<any>;

    constructor(clientInfo: ClientInfo) {
        super();
        this.clientInfo = clientInfo;
        this.bonjourBrowser = new HAPBonjourBrowser(clientInfo);

        this.bonjourBrowser.on(BonjourBrowserEvents.UPDATE, this.deviceInfoUpdated.bind(this));
        this.bonjourBrowser.on(BonjourBrowserEvents.CONFIG_NUMBER_CHANGE, (num: number) => {
            this.emit(HAPClientEvents.CONFIG_NUMBER_CHANGE, num);
        });

        this.currentChain = Promise.resolve()
            .then(() => this.clientInfo.load()) // transparently load ClientInfo from disk
            .then(() => debug("Loaded ClientInfo for '%s'", this.clientInfo.clientId))
            .then(() => this.bonjourBrowser.deviceInfoPromise())// TODO startup should fail correctly when this promise returns from timeout
            .then(deviceInfo => this.deviceInfo = deviceInfo);
    }

    private deviceInfoUpdated(deviceInfo: HAPDeviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    newConnection() {
        const connection = new HAPClientConnection(this);
        connection.on(HAPClientConnectionEvents.DISCONNECTED, this.handleDisconnected.bind(this, connection));

        this.connections.push(connection);

        return connection
    }

    ensureConnected(connection: HAPClientConnection) {
        return this.currentChain = this.currentChain
            .then(() => connection.ensureConnected());
    }

    checkPaired(connection: HAPClientConnection): Promise<void> {
        return this.currentChain = this.currentChain
            .then(() => this.clientInfo.paired? Promise.resolve(): this.sendPairM1(connection));
    }

    private sendPairM1(connection: HAPClientConnection): Promise<void> {
        debugCon("Sending pair setup M1");

        this.pairSetupSession = {
            initiator: connection,
        };

        const startRequest = tlv.encode(
            TLVValues.STATE, HAPStates.M1,
            TLVValues.METHOD, PairMethods.PAIR_SETUP,
        );

        return connection.sendPairRequest(HTTPRoutes.PAIR_SETUP, startRequest)
            .then(this.handlePairM2.bind(this, connection));
    }

    private handlePairM2(connection: HAPClientConnection, response: HTTPResponse): Promise<void> {
        debugCon("Received pair setup M2 response");

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE][0];
        assert(state === HAPStates.M2, "Response was not in state M2");

        if (objects[TLVValues.ERROR]) {
            debugCon("M2: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
            connection.disconnect();
            return Promise.reject("M2: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
        }

        const serverPublicKey = objects[TLVValues.PUBLIC_KEY];
        const salt = objects[TLVValues.SALT];
        return this.sendPairM3(connection, serverPublicKey, salt);
    }

    private sendPairM3(connection: HAPClientConnection, serverPublicKey: Buffer, salt: Buffer): Promise<void> {
        debugCon("Sending pair setup M3");

        return this.clientInfo.pincode().then(pinCode => SRP.genKey(32).then(key => {
            const srpParams = SRP.params.hap;
            const client = new SrpClient(srpParams, salt, Buffer.from("Pair-Setup"), Buffer.from(pinCode), key!);
            this.pairSetupSession!.srpClient = client;

            client.setB(serverPublicKey);
            const A = client.computeA();
            const M1 = client.computeM1();

            const verifyRequest = tlv.encode(
              TLVValues.STATE, HAPStates.M3,
              TLVValues.PUBLIC_KEY, A,
              TLVValues.PASSWORD_PROOF, M1,
            );

            return connection.sendPairRequest(HTTPRoutes.PAIR_SETUP, verifyRequest)
              .then(this.handlePairM4.bind(this, connection))
        }));
    }

    private handlePairM4(connection: HAPClientConnection, response: HTTPResponse): Promise<void> {
        debugCon("Received pair setup M4 response");

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE][0];
        assert(state === HAPStates.M4, "Response was not in state M4");

        if (objects[TLVValues.ERROR]) {
            debugCon("M4: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
            connection.disconnect();
            return Promise.reject("M4: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
        }

        const session = this.pairSetupSession!;
        const srpClient = session.srpClient!;

        const serverProof = objects[TLVValues.PASSWORD_PROOF];
        const encryptedData = objects[TLVValues.ENCRYPTED_DATA];

        try {
            srpClient.checkM2(serverProof);
        } catch (error) {
            debugCon("ERROR: srp serverProof could not be verified: " + error.message);
            connection.disconnect();
            return Promise.reject("ERROR: srp serverProof could not be verified: " + error.message);
        }

        if (encryptedData) {
            debugCon("Received MFI challenge, ignoring it");
        }

        session.sharedSecret = srpClient.computeK();

        return this.sendPairM5(connection);
    }

    private sendPairM5(connection: HAPClientConnection): Promise<void> {
        debugCon("Sending pair setup M5");
        const session = this.pairSetupSession!;
        const sharedSecret = session.sharedSecret!;

        // step 1 (LT keys already generated)

        // step 2
        let salt = Buffer.from("Pair-Setup-Controller-Sign-Salt");
        let info = Buffer.from("Pair-Setup-Controller-Sign-Info");
        const iOSDeviceX = encryption.HKDF("sha512", salt, sharedSecret, info, 32);

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
        session.sessionKey = encryption.HKDF("sha512", salt, sharedSecret, info, 32);

        const nonce = Buffer.from("PS-Msg05");
        const encrypted = encryption.chacha20_poly1305_encryptAndSeal(session.sessionKey, nonce, null, subTLV);
        const encryptedData = encrypted.ciphertext;
        const authTag = encrypted.authTag;

        // step 7
        const exchangeRequest = tlv.encode(
            TLVValues.STATE, HAPStates.M5,
            TLVValues.ENCRYPTED_DATA, Buffer.concat([encryptedData, authTag]),
        );

        return connection.sendPairRequest(HTTPRoutes.PAIR_SETUP, exchangeRequest)
            .then(this.handlePairM6.bind(this, connection));
    }

    private handlePairM6(connection: HAPClientConnection, response: HTTPResponse): Promise<void> {
        debugCon("Received pair setup M6 response");
        const session = this.pairSetupSession!;

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE][0];
        assert(state === HAPStates.M6, "Response was not in state M6");

        if (objects[TLVValues.ERROR]) {
            debugCon("M6: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
            connection.disconnect();
            return Promise.reject("M6: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
        }

        // step 1 + 2
        const encryptedDataContent = objects[TLVValues.ENCRYPTED_DATA];
        const encryptedData = encryptedDataContent.slice(0, -16);
        const authTag = encryptedDataContent.slice(-16);

        const nonce = Buffer.from("PS-Msg06");
        let plaintextBuffer;
        try {
            plaintextBuffer = encryption.chacha20_poly1305_decryptAndVerify(session.sessionKey!, nonce, null, encryptedData, authTag);
        } catch (error) {
            debugCon("M6: Could not verify and decrypt: " + error.stack);
            connection.disconnect();
            return Promise.reject("M6: Could not verify and decrypt!");
        }

        const subTLV = tlv.decode(plaintextBuffer);
        const accessoryIdentifier = subTLV[TLVValues.IDENTIFIER];
        const accessoryLTPK = subTLV[TLVValues.PUBLIC_KEY];
        const accessorySignature = subTLV[TLVValues.SIGNATURE];

        // step 3
        const salt = Buffer.from("Pair-Setup-Accessory-Sign-Salt");
        const info = Buffer.from("Pair-Setup-Accessory-Sign-Info");
        const accessoryX = encryption.HKDF("sha512", salt, session.srpClient!.computeK(), info, 32);

        const accessoryInfo = Buffer.concat([
            accessoryX,
            accessoryIdentifier,
            accessoryLTPK,
        ]);
        if (!tweetnacl.sign.detached.verify(accessoryInfo, accessorySignature, accessoryLTPK)) {
            debugCon("M6: Could not verify accessory signature!");
            connection.disconnect();
            return Promise.reject("Could not verify accessory signature!");
        }

        this.clientInfo.accessoryIdentifier = accessoryIdentifier.toString();
        this.clientInfo.accessoryLTPK = accessoryLTPK;
        this.clientInfo.paired = true;

        this.pairSetupSession = undefined;

        debugCon("Successfully paired with %s", accessoryIdentifier.toString());

        return this.clientInfo.save();
    }

    private handleDisconnected(connection: HAPClientConnection) {
        // TODO debug("Connection disconnected %s:%d!", connection.remoteAddress.address, connection.remoteAddress.port);

        if (this.pairSetupSession && this.pairSetupSession.initiator === connection) {
            this.pairSetupSession = undefined;
        }

        const index = this.connections.indexOf(connection);
        if (index >= 0) {
            this.connections.splice(index, 1);
        }
    }

}

export enum HAPClientConnectionEvents {
    EVENT_RAW = "event-raw",
    DISCONNECTED = "disconnected",
}

export type HAPClientConnectionEventMap = {
    [HAPClientConnectionEvents.EVENT_RAW]: (eventBuf: Buffer) => void;
    [HAPClientConnectionEvents.DISCONNECTED]: () => void;
}

export class HAPClientConnection extends EventEmitter<HAPClientConnectionEventMap> {

    private socket?: Socket;
    private parser: HTTPResponseParser;

    private readonly client: HAPClient;
    private readonly clientInfo: ClientInfo;

    private pairVerifySession?: Partial<PairVerifySession>;
    private pairingVerified = false;
    encryptionContext?: HAPEncryptionContext;

    private socketClosed: boolean = false;

    private socketConnectReject?: (reason?: any) => void;
    private httpRequestResolver?: (value?: HTTPResponse | PromiseLike<HTTPResponse>) => void;

    private connectionChain: Promise<any>;

    constructor(client: HAPClient) {
        super();
        this.parser = new HTTPResponseParser();

        this.client = client;
        this.clientInfo = client.clientInfo;

        this.connectionChain = Promise.resolve();
    }

    // should not be called directly
    ensureConnected(): Promise<void> {
        if (this.socket && !this.socketClosed) {
            return Promise.resolve();
        }

        if (!this.client.deviceInfo) {
            return Promise.reject("ensureConnected() should not be called directly on the connection object!");
        }

        debugCon("Opening socket...");

        this.socketClosed = false;

        this.socket = net.createConnection(this.client.deviceInfo.port, this.client.deviceInfo.host);
        this.socket.on('data', this.handleIncomingData.bind(this));
        this.socket.on('error', this.handleError.bind(this));
        this.socket.on('close', this.handleClosed.bind(this));

        this.socket.setKeepAlive(true);
        this.socket.setNoDelay(true);

        return new Promise<void>((resolve, reject) => {
            this.socketConnectReject = reject;

            this.socket!.on('connect', () => {
                debugCon("Successfully connected!");
                this.socketConnectReject = undefined;
                resolve();
            });
        });
    }

    disconnect() {
        if (this.socket && !this.socketClosed) {
            this.socket.end();
            this.socketClosed = true;
        }
    }

    ensurePairingVerified() {
        return this.connectionChain = this.connectionChain
            .then(() => this.client.ensureConnected(this))
            .then(() => this.client.checkPaired(this))
            .then(() => this.pairingVerified? Promise.resolve(): this.sendPairVerifyM1());
    }

    accessories(): Promise<HTTPResponse> {
        return this.connectionChain = this.ensurePairingVerified()
            .then(() => this.get(HTTPRoutes.ACCESSORIES));
    }

    getCharacteristics(characteristics: CharacteristicReadRequest[], event?: boolean, meta?: boolean, perms?: boolean, type?: boolean): Promise<HTTPResponse> {
        const queryParams: Record<string, string> = {};

        let id = "";
        characteristics.forEach(request => {
            if (id.length) {
                id += ","
            }

            id += request.aid + "." + request.iid;
        });

        queryParams["id"] = id;
        if (event) {
            queryParams["ev"] = "1";
        }
        if (meta) {
            queryParams["meta"] = "1";
        }
        if (perms) {
            queryParams["perms"] = "1";
        }
        if (type) {
            queryParams["type"] = "1";
        }

        return this.getCharacteristicsRaw(queryParams);
    }

    getCharacteristicsRaw(queryParams: ParsedUrlQuery): Promise<HTTPResponse> {
        return this.connectionChain = this.ensurePairingVerified()
            .then(() => this.get(HTTPRoutes.CHARACTERISTICS, queryParams));
    }

    setCharacteristics(characteristics: CharacteristicWriteRequest[], pid?: number): Promise<HTTPResponse> {
        const request: CharacteristicsWriteRequest = {
            characteristics: characteristics,
            pid: pid,
        };

        const body = Buffer.from(JSON.stringify(request));
        return this.setCharacteristicsRaw(body);
    }

    setCharacteristicEvents(characteristics: CharacteristicEventRequest[], pid?: number) {
        const request = {
            characteristics: characteristics,
            pid: pid,
        };

        const body = Buffer.from(JSON.stringify(request));
        return this.setCharacteristicsRaw(body);
    }

    setCharacteristicsRaw(writeRequest: Buffer): Promise<HTTPResponse> {
        return this.connectionChain = this.ensurePairingVerified()
            .then(() => this.put(HTTPRoutes.CHARACTERISTICS, writeRequest));
    }

    prepareWrite(ttl: number, pid?: number): Promise<number> {
        if (pid === undefined) {
            pid = this.generatePid();
        }

        const body = Buffer.from(JSON.stringify({
            ttl: ttl,
            pid: pid,
        }));

        return this.connectionChain = this.ensurePairingVerified()
            .then(() => this.put(HTTPRoutes.PREPARE, body))
            .then(response => new Promise((resolve, reject) => {
                const responseStatus = JSON.parse(response.body.toString());
                if (responseStatus.status === 0) {
                    resolve(pid);
                } else {
                    reject(responseStatus.status);
                }
            }));
    }

    prepareWriteRaw(prepareRequest: Buffer): Promise<HTTPResponse> {
        return this.connectionChain = this.ensurePairingVerified()
            .then(() => this.put(HTTPRoutes.PREPARE, prepareRequest));
    }

    generatePid(): number {
        const ran = crypto.randomBytes(2);
        return ran.readUInt16LE(0);
    }

    // TODO /resource

    resourceRaw(resourceRequest: Buffer): Promise<HTTPResponse> {
        return this.connectionChain = this.ensurePairingVerified()
            .then(() => this.post(HTTPRoutes.RESOURCE, resourceRequest));
    }

    // TODO addPairing

    // TODO listPairings

    /**
     * Sends the request to remove a pairing. When clientId is omitted the own pairing will be removed.
     *
     * @param clientInfo {ClientInfo} - clientInfo of the pairing which will be removed (optional, defaults to own id)
     */
    removePairing(clientInfo: ClientInfo = this.clientInfo) {
        // step 1
        if (!clientInfo) {
            clientInfo = this.clientInfo;
        }

        // step 2
        const requestTLV = tlv.encode(
            TLVValues.STATE, HAPStates.M1,
            TLVValues.METHOD, PairMethods.REMOVE_PAIRING,
            TLVValues.IDENTIFIER, Buffer.from(clientInfo.clientId),
        );

        // step 3
        return this.connectionChain = this.ensurePairingVerified()
            .then(() => this.sendPairRequest(HTTPRoutes.PAIRINGS, requestTLV))
            .then((response) => {
                const body = response.body;
                const responseTlv = tlv.decode(body);

                const error = responseTlv[TLVValues.ERROR];
                if (error) {
                    const errorCode = error.readUInt8(0);
                    debug("Error removing pairing: " + TLVErrors[errorCode]);
                    throw new Error(errorCode + "");
                } else {
                    clientInfo.paired = false;
                    return clientInfo.save();
                }
            });
    }

    private sendPairVerifyM1(): Promise<void> {
        debugCon("Sending pair-verify M1");

        const keyPair = encryption.generateCurve25519KeyPair();
        const secretKey = Buffer.from(keyPair.secretKey);
        const publicKey = Buffer.from(keyPair.publicKey);

        this.pairVerifySession = {
            secretKey: secretKey,
            publicKey: publicKey,
        };

        const startRequest = tlv.encode(
            TLVValues.STATE, HAPStates.M1,
            TLVValues.PUBLIC_KEY, publicKey
        );

        return this.sendPairRequest(HTTPRoutes.PAIR_VERIFY, startRequest)
            .then(this.handlePairVerifyM2.bind(this));
    }

    private handlePairVerifyM2(response: HTTPResponse): Promise<void> {
        debugCon("Received pair-verify M2");

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE].readUInt8(0);
        const error = objects[TLVValues.ERROR];
        const serverPublicKey = objects[TLVValues.PUBLIC_KEY];
        const encryptedData = objects[TLVValues.ENCRYPTED_DATA];

        assert.strictEqual(state, HAPStates.M2, "PairVerify state did not match M2");

        if (error) {
            debugCon("Pair-Verify M2 returned with error: " + TLVErrors[error[0]]);
            this.disconnect();
            return Promise.reject("Pair-Verify M2 returned with error: " + TLVErrors[error[0]]);
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
        const sessionKey = encryption.HKDF("sha512", encryptionSalt, sharedSecret, encryptionInfo, 32);

        session.sharedSecret = sharedSecret;

        // Step 3 & 4
        const cipherText = encryptedData.slice(0, -16);
        const authTag = encryptedData.slice(-16);

        const nonce = Buffer.from("PV-Msg02");
        let plaintext;
        try {
           plaintext = encryption.chacha20_poly1305_decryptAndVerify(sessionKey, nonce, null, cipherText, authTag);
        } catch (error) {
            console.error("WARNING: M2 - Could not verify cipherText: " + error.stack);
            this.disconnect();
            return Promise.reject("WARNING: M2 - Could not verify cipherText");
        }

        // Step 5
        const data = tlv.decode(plaintext);
        const accessoryIdentifier = data[TLVValues.IDENTIFIER];
        const accessorySignature = data[TLVValues.SIGNATURE];

        // we would need to lookup our pairing (retrieve accessoryLTPK).
        // We do however only support one pairing, thus check if ids match
        if (this.clientInfo.accessoryIdentifier !== accessoryIdentifier.toString()) {
            console.error("WARNING: identifier is not the expected store in the keystore");
            this.disconnect();
            return Promise.reject("WARNING: identifier is not the expected store in the keystore");
        }

        // Step 6
        const accessoryInfo = Buffer.concat([
            serverPublicKey,
            accessoryIdentifier,
            session.publicKey!
        ]);

        if (!tweetnacl.sign.detached.verify(accessoryInfo, accessorySignature, this.clientInfo.accessoryLTPK)) {
            debugCon("M2: Failed in pair-verify to verify accessory signature!");
            this.disconnect();
            return Promise.reject("M2: Failed in pair-verify to verify accessory signature!");
        }

        return this.sendPairVerifyM3(serverPublicKey, sessionKey);
    }

    private sendPairVerifyM3(serverPublicKey: Buffer, encryptionKey: Buffer): Promise<void> {
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
        const nonce = Buffer.from("PV-Msg03");
        const encrypted = encryption.chacha20_poly1305_encryptAndSeal(encryptionKey, nonce, null, plainTextTLV);

        // Step 11
        const finishRequest = tlv.encode(
            TLVValues.STATE, HAPStates.M3,
            TLVValues.ENCRYPTED_DATA, Buffer.concat([encrypted.ciphertext, encrypted.authTag]),
        );

        // Step 12
        return this.sendPairRequest(HTTPRoutes.PAIR_VERIFY, finishRequest)
            .then(this.handlePairVerifyM4.bind(this));
    }

    private handlePairVerifyM4(response: HTTPResponse): Promise<void> {
        debugCon("Received pair-verify step M4");

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE].readUInt8(0);
        const error = objects[TLVValues.ERROR];

        assert.strictEqual(state, HAPStates.M4, "PairVerify state did not match M4");

        const session = this.pairVerifySession!;
        const sharedSecret = session.sharedSecret!;

        this.pairVerifySession = undefined;
        if (error) {
            debugCon("Pair-Verify was unsuccessful: " + TLVErrors[error[0]]);
            this.disconnect();
            return Promise.reject("pair-verify was unsuccessful: " + TLVErrors[error[0]]);
        } else {
            // generate HAP encryption/decryption keys
            const salt = Buffer.from("Control-Salt");
            const accessoryToControllerInfo = Buffer.from("Control-Read-Encryption-Key");
            const controllerToAccessoryInfo = Buffer.from("Control-Write-Encryption-Key");

            const accessoryToControllerKey = encryption.HKDF("sha512", salt, sharedSecret, accessoryToControllerInfo, 32);
            const controllerToAccessoryKey = encryption.HKDF("sha512", salt, sharedSecret, controllerToAccessoryInfo, 32);

            this.encryptionContext = new HAPEncryptionContext(sharedSecret, controllerToAccessoryKey, accessoryToControllerKey);
            this.pairingVerified = true;

            debugCon("Pair-Verify was successful");

            return Promise.resolve();
        }
    }

    private handleIncomingData(data: Buffer) {
        if (this.socketClosed) {
            return;
        }

        if (this.encryptionContext) {
            try {
                data = encryption.layerDecrypt(data, this.encryptionContext);
            } catch (error) {
                // decryption failed
                this.disconnect();
                return;
            }
        }

        this.parser.appendData(data);

        const messages: HTTPResponse[] = this.parser.parse();

        messages.forEach(message => {
            if (message.messageType === "EVENT") {
                this.emit(HAPClientConnectionEvents.EVENT_RAW, message.body);
            } else if (message.messageType === "HTTP") {
                if (this.httpRequestResolver) {
                    const resolve = this.httpRequestResolver;
                    this.httpRequestResolver = undefined;
                    resolve(message);
                } else {
                    console.error("WARNING: Received http response when not expecting anything!");
                }
            } else {
                console.error("WARNING: Received unknown message type!");
            }
        })
    }

    get(route: HTTPRoutes, queryParams: ParsedUrlQuery = {}, headers: Record<string, string> = {}): Promise<HTTPResponse> {
        return this.sendRequest(HTTPMethod.GET, route, HTTPContentType.HAP_JSON, queryParams, headers);
    }

    put(route: HTTPRoutes, data: Buffer, queryParams: Record<string, string> = {}, headers: Record<string,string> = {}): Promise<HTTPResponse> {
        return this.sendRequest(HTTPMethod.PUT, route, HTTPContentType.HAP_JSON, queryParams, headers, data);
    }

    post(route: HTTPRoutes, data: Buffer, queryParams: Record<string, string> = {}, headers: Record<string,string> = {}): Promise<HTTPResponse> {
        return this.sendRequest(HTTPMethod.POST, route, HTTPContentType.HAP_JSON, queryParams, headers, data);
    }

    sendPairRequest(route: HTTPRoutes, data?: Buffer): Promise<HTTPResponse> {
        return this.sendRequest(HTTPMethod.POST, route, HTTPContentType.PAIRING_TLV8, {}, {}, data);
    }

    private sendRequest(method: HTTPMethod, route: HTTPRoutes, contentType: HTTPContentType,
                        queryParams: ParsedUrlQuery = {}, headers: Record<string, string> = {}, data?: Buffer): Promise<HTTPResponse> {
        if (!this.socket || this.socketClosed) {
            return Promise.reject("Connection was not established!");
        }

        if (this.httpRequestResolver) {
            console.error("WARNING: http request still in progress");
            return Promise.reject("Request still in progress");
        }

        headers["Content-Type"] = contentType;
        if (data && (method === HTTPMethod.POST || method === HTTPMethod.PUT)) {
            headers["Content-Length"] = data.length + "";
        } else {
            data = Buffer.alloc(0);
        }

        let query = "";
        Object.entries(queryParams).forEach(([key, value])=> {
            if (typeof value === "string") {
                if (query.length) {
                    query += ","
                }

                query += key + "=" + value;
            } else {
                value.forEach(value0 => {
                    if (query.length) {
                        query += ","
                    }

                    query += key + "=" + value0;
                });
            }
        });
        if (query) {
            query = "?" + query;
        }

        let request = Buffer.concat([
            Buffer.from(
                `${method} ${route + query} HTTP/1.1\r\n` +
                `Host: ${this.client.deviceInfo!.host}:${this.client.deviceInfo!.port}\r\n` +
                Object.keys(headers).reduce((acc: string, header: string) => {
                    return acc + `${header}: ${headers[header]}\r\n`;
                }, "") +
                `\r\n` // additional newline before content
            ),
            data
        ]);


        if (this.encryptionContext) {
            request = encryption.layerEncrypt(request, this.encryptionContext);
        }

        return new Promise<HTTPResponse>(resolve => {
            this.httpRequestResolver = resolve;
            this.socket!.write(request);
        });
    }

    private handleError(error: Error) {
        // TODO log
        if (this.socketConnectReject) {
            this.socketConnectReject(error);
        }
    }

    private handleClosed() {
        this.socket = undefined;
        this.pairVerifySession = undefined;
        this.pairingVerified = false;
        this.encryptionContext = undefined;
        this.httpRequestResolver = undefined;

        this.parser = new HTTPResponseParser(); // ensure parser buffer is cleared up

        debugCon("Disconnected!"); // TODO debug

        this.emit(HAPClientConnectionEvents.DISCONNECTED);
    }

}
