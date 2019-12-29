import net, {Socket} from 'net';
import createDebug from 'debug';
import assert from 'assert';
import crypto from 'crypto';
import * as tlv from './lib/utils/tlv';
import * as encryption from './lib/crypto/encryption';
import * as hkdf from './lib/crypto/hkdf';
import tweetnacl from 'tweetnacl';
import srp from 'fast-srp-hap';
import {HTTPContentType, HTTPMethod, HTTPResponse, HTTPResponseParser, HTTPRoutes} from "./lib/http-protocol";
import {ClientInfo} from "./lib/storage/ClientInfo";
import {EventEmitter} from "./lib/EventEmitter";
import {HAPEncryptionContext, HAPStates, PairMethods, TLVErrors, TLVValues} from "./types/hap-proxy";

const debug = createDebug("HAPClient");
const debugCon = createDebug("HAPClient:Connection");

export type PinProvider = (callback: (pinCode: string) => void) => void;
export type ResponseHandler = (response: HTTPResponse) => void;

export interface Characteristic {
    aid: number,
    iid: number,
}

export interface CharacteristicsGetRequest extends Characteristic {}

export interface CharacteristicsSetRequest extends Characteristic {
    value: any,
    ev?: boolean,
    authData?: string,
    remote?: string,
    r?: string, // write response
}

export interface CharacteristicsEventRequest extends Characteristic {
    ev: boolean,
}

export interface CharacteristicsEventResponse extends Characteristic {
    value: any,
}

export type ClientPairSetupSession = {
    pinProvider: PinProvider,
    srpClient: srp.Client,
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
    EVENT_RAW = "event-raw",
}

export type HAPClientEventMap = {
    [HAPClientEvents.EVENT_RAW]: (eventBuf: Buffer) => void;
}

export class HAPClient extends EventEmitter<HAPClientEventMap> {

    clientInfo: ClientInfo;

    host: string;
    port: number;
    private readonly pinProvider: PinProvider;

    connection: HAPClientConnection;
    private pairSetupSession?: Partial<ClientPairSetupSession>;
    private pairVerifySession?: Partial<PairVerifySession>;
    private pairingVerified = false;

    private currentChain: Promise<any> = Promise.resolve();

    static async loadClient(clientId: string, host: string, port: number, pinProvider: PinProvider) {
        clientId = clientId.toUpperCase();
        debug("Loading clientInfo for '%s'", clientId);
        const clientInfo = await ClientInfo.loadOrCreate(clientId);

        return new HAPClient(clientInfo, host, port, pinProvider);
    }

    private constructor(clientInfo: ClientInfo, host: string, port: number, pinProvider: PinProvider) {
        super();
        this.clientInfo = clientInfo;
        this.host = host;
        this.port = port;
        this.pinProvider = pinProvider;

        this.connection = new HAPClientConnection(this);
        this.connection.on(HAPClientConnectionEvents.EVENT_RAW, this.handleEvents.bind(this));
        this.connection.on(HAPClientConnectionEvents.DISCONNECTED, this.handleDisconnected.bind(this));
    }

    accessories(): Promise<HTTPResponse> {
        return this.currentChain = this.ensurePairingVerified()
            .then(() => this.connection.get(HTTPRoutes.ACCESSORIES));
    }

    getCharacteristics(characteristics: CharacteristicsGetRequest[], event?: boolean, meta?: boolean, perms?: boolean, type?: boolean): Promise<HTTPResponse> {
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

        return this.currentChain = this.ensurePairingVerified()
            .then(() => this.connection.get(HTTPRoutes.CHARACTERISTICS, queryParams));
    }

    setCharacteristics(characteristics: CharacteristicsSetRequest[], pid?: number): Promise<HTTPResponse> {
        const request = {
            characteristics: characteristics,
            pid: pid,
        };

        const body = Buffer.from(JSON.stringify(request));

        return this.currentChain = this.ensurePairingVerified()
            .then(() => this.connection.put(HTTPRoutes.CHARACTERISTICS, body));
    }

    setCharacteristicEvents(characteristics: CharacteristicsEventRequest[], pid?: number) {
        const request = {
            characteristics: characteristics,
            pid: pid,
        };

        const body = Buffer.from(JSON.stringify(request));

        return this.currentChain = this.ensurePairingVerified()
            .then(() => this.connection.put(HTTPRoutes.CHARACTERISTICS, body));
    }

    prepareWrite(ttl: number, pid?: number): Promise<number> {
        if (pid === undefined) {
            pid = this.genRandomPid();
        }

        const body = Buffer.from(JSON.stringify({
            ttl: ttl,
            pid: pid,
        }));

        return this.currentChain = this.ensurePairingVerified()
            .then(() => this.connection.put(HTTPRoutes.PREPARE, body))
            .then(response => new Promise((resolve, reject) => {
                const responseStatus = JSON.parse(response.body.toString());
                if (responseStatus.status === 0) {
                    resolve(pid);
                } else {
                    reject(responseStatus.status);
                }
            }));
    }

    // TODO /resource

    // TODO addPairing

    // TODO listPairings

    /**
     * Sends the request to remove a pairing. When clientId is omitted the own pairing will be removed.
     *
     * @param clientId - identifier of the pairing which will be removed (optional, defaults to own id)
     */
    removePairing(clientId?: string) {
        // step 1
        if (!clientId) {
            clientId = this.clientInfo.clientId;
        }

        // step 2
        const requestTLV = tlv.encode(
            TLVValues.STATE, HAPStates.M1,
            TLVValues.METHOD, PairMethods.REMOVE_PAIRING,
            TLVValues.IDENTIFIER, Buffer.from(clientId),
        );

        // step 3
        return this.currentChain = this.ensurePairingVerified()
            .then(() => this.connection.sendPairRequest(HTTPRoutes.PAIRINGS, requestTLV))
            .then(response => {
                const body = response.body;
                const responseTlv = tlv.decode(body);
                // TODO validate response

                console.log("received pairings body tlv");
                console.log(responseTlv);
            });
    }

    genRandomPid(): number {
        const ran = crypto.randomBytes(2);
        return ran.readUInt16LE(0);
    }

    private ensurePairingVerified() {
        return this.currentChain = this.currentChain
            .then(() => this.connection.ensureConnected())
            .then(() => this.ensureAuthenticated());
    }

    private ensureAuthenticated(): Promise<void> {
        return this.checkPaired(this.pinProvider)
            .then(this.pairVerify.bind(this));
    }

    private checkPaired(pin: PinProvider): Promise<void> {
        if (this.clientInfo.paired) {
            return Promise.resolve();
        }

        this.pairSetupSession = {
            pinProvider: pin,
        };
        return this.sendPairM1();
    }

    private pairVerify(): Promise<void> {
        if (this.pairingVerified) {
            return Promise.resolve();
        }

        return this.sendPairVerifyM1();
    }

    private sendPairM1(): Promise<void> {
        debugCon("Sending pair setup M1");

        const startRequest = tlv.encode(
            TLVValues.STATE, HAPStates.M1,
            TLVValues.METHOD, PairMethods.PAIR_SETUP,
        );

        return this.connection.sendPairRequest(HTTPRoutes.PAIR_SETUP, startRequest)
            .then(this.handlePairM2.bind(this));
    }

    private handlePairM2(response: HTTPResponse): Promise<void> {
        debugCon("Received pair setup M2 response");

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE][0];
        assert(state === HAPStates.M2, "Response was not in state M2");

        if (objects[TLVValues.ERROR]) {
            debugCon("M2: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
            this.connection.disconnect();
            return Promise.reject("M2: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
        }

        const serverPublicKey = objects[TLVValues.PUBLIC_KEY];
        const salt = objects[TLVValues.SALT];
        return this.sendPairM3(serverPublicKey, salt);
    }

    private sendPairM3(serverPublicKey: Buffer, salt: Buffer): Promise<void> {
        debugCon("Sending pair setup M3");

        return new Promise<void>(resolve => {
            this.pairSetupSession!.pinProvider!(pinCode => {
                srp.genKey(32, (err, key) => {
                    const srpParams = srp.params['3072'];
                    const client = new srp.Client(srpParams, salt, Buffer.from("Pair-Setup"), Buffer.from(pinCode), key);
                    this.pairSetupSession!.srpClient = client;

                    client.setB(serverPublicKey);
                    const A = client.computeA();
                    const M1 = client.computeM1();

                    const verifyRequest = tlv.encode(
                        TLVValues.STATE, HAPStates.M3,
                        TLVValues.PUBLIC_KEY, A,
                        TLVValues.PROOF, M1,
                    );

                    this.connection.sendPairRequest(HTTPRoutes.PAIR_SETUP, verifyRequest)
                        .then(this.handlePairM4.bind(this))
                        .then(resolve);
                });
            });
        })
    }

    private handlePairM4(response: HTTPResponse): Promise<void> {
        debugCon("Received pair setup M4 response");

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE][0];
        assert(state === HAPStates.M4, "Response was not in state M4");

        if (objects[TLVValues.ERROR]) {
            debugCon("M4: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
            this.connection.disconnect();
            return Promise.reject("M4: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
        }

        const session = this.pairSetupSession!;
        const srpClient = session.srpClient!;

        const serverProof = objects[TLVValues.PROOF];
        const encryptedData = objects[TLVValues.ENCRYPTED_DATA];

        try {
            srpClient.checkM2(serverProof);
        } catch (error) {
            debugCon("ERROR: srp serverProof could not be verified: " + error.message);
            this.connection.disconnect();
            return Promise.reject("ERROR: srp serverProof could not be verified: " + error.message);
        }

        if (encryptedData) {
            debugCon("Received MFI challenge, ignoring it");
        }

        return this.sendPairM5();
    }

    private sendPairM5(): Promise<void> {
        debugCon("Sending pair setup M5");
        const session = this.pairSetupSession!;
        const srpClient = session.srpClient!;

        // step 1 (LT keys already generated)

        // step 2
        let salt = Buffer.from("Pair-Setup-Controller-Sign-Salt");
        let info = Buffer.from("Pair-Setup-Controller-Sign-Info");
        // TODO save shared secret in field. no need to use srpClient here
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
        session.sessionKey = hkdf.HKDF("sha512", salt, srpClient.computeK(), info, 32);

        const nonce = Buffer.from("PS-Msg05");
        const encryptedData = Buffer.alloc(subTLV.length);
        const authTag = Buffer.alloc(16);
        encryption.encryptAndSeal(session.sessionKey, nonce, subTLV, null, encryptedData, authTag);

        // step 7
        const exchangeRequest = tlv.encode(
            TLVValues.STATE, HAPStates.M5,
            TLVValues.ENCRYPTED_DATA, Buffer.concat([encryptedData, authTag]),
        );

        return this.connection.sendPairRequest(HTTPRoutes.PAIR_SETUP, exchangeRequest)
            .then(this.handlePairM6.bind(this));
    }

    private handlePairM6(response: HTTPResponse): Promise<void> {
        debugCon("Received pair setup M6 response");
        const session = this.pairSetupSession!;

        const objects = tlv.decode(response.body);
        const state = objects[TLVValues.STATE][0];
        assert(state === HAPStates.M6, "Response was not in state M6");

        if (objects[TLVValues.ERROR]) {
            debugCon("M6: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
            this.connection.disconnect();
            return Promise.reject("M6: received error code " + TLVErrors[objects[TLVValues.ERROR][0]]);
        }

        // step 1 + 2
        const encryptedDataContent = objects[TLVValues.ENCRYPTED_DATA];
        const encryptedData = encryptedDataContent.slice(0, -16);
        const authTag = encryptedDataContent.slice(-16);

        const nonce = Buffer.from("PS-Msg06");
        const plaintextBuffer = Buffer.alloc(encryptedData.length);
        if (!encryption.verifyAndDecrypt(session.sessionKey!, nonce, encryptedData, authTag, null, plaintextBuffer)) {
            debugCon("M6: Could not verify and decrypt!");
            this.connection.disconnect();
            return Promise.reject("M6: Could not verify and decrypt!");
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
            this.connection.disconnect();
            return Promise.reject("Could not verify accessory signature!");
        }

        this.clientInfo.accessoryIdentifier = accessoryIdentifier.toString();
        this.clientInfo.accessoryLTPK = accessoryLTPK;
        this.clientInfo.paired = true;

        this.pairSetupSession = undefined;

        debugCon("Successfully paired with %s", accessoryIdentifier.toString());

        return this.clientInfo.save();
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

        return this.connection.sendPairRequest(HTTPRoutes.PAIR_VERIFY, startRequest)
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
            this.connection.disconnect();
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
        const sessionKey = hkdf.HKDF("sha512", encryptionSalt, sharedSecret, encryptionInfo, 32);

        session.sharedSecret = sharedSecret;

        // Step 3 & 4
        const cipherText = encryptedData.slice(0, -16);
        const authTag = encryptedData.slice(-16);
        const plaintext = Buffer.alloc(cipherText.length);

        const nonce = Buffer.from("PV-Msg02");
        if (!encryption.verifyAndDecrypt(sessionKey, nonce, cipherText, authTag, null, plaintext)) {
            console.error("WARNING: M2 - Could not verify cipherText");
            this.connection.disconnect();
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
            this.connection.disconnect();
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
            this.connection.disconnect();
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
        const cipherText = Buffer.alloc(plainTextTLV.length);
        const authTag = Buffer.alloc(16);
        const nonce = Buffer.from("PV-Msg03");
        encryption.encryptAndSeal(encryptionKey, nonce, plainTextTLV, null, cipherText, authTag);

        // Step 11
        const finishRequest = tlv.encode(
            TLVValues.STATE, HAPStates.M3,
            TLVValues.ENCRYPTED_DATA, Buffer.concat([cipherText, authTag]),
        );

        // Step 12
        return this.connection.sendPairRequest(HTTPRoutes.PAIR_VERIFY, finishRequest)
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
            this.connection.disconnect();
            return Promise.reject("pair-verify was unsuccessful: " + TLVErrors[error[0]]);
        } else {
            // generate HAP encryption/decryption keys
            const salt = Buffer.from("Control-Salt");
            const accessoryToControllerInfo = Buffer.from("Control-Read-Encryption-Key");
            const controllerToAccessoryInfo = Buffer.from("Control-Write-Encryption-Key");

            const accessoryToControllerKey = hkdf.HKDF("sha512", salt, sharedSecret, accessoryToControllerInfo, 32);
            const controllerToAccessoryKey = hkdf.HKDF("sha512", salt, sharedSecret, controllerToAccessoryInfo, 32);

            this.connection.encryptionContext = new HAPEncryptionContext(sharedSecret, controllerToAccessoryKey, accessoryToControllerKey);
            this.pairingVerified = true;

            debugCon("Pair-Verify was successful");

            return Promise.resolve();
        }
    }

    private handleEvents(eventBuf: Buffer) {
        this.emit(HAPClientEvents.EVENT_RAW, eventBuf);
    }

    private handleDisconnected() {
        this.pairVerifySession = undefined;
        this.pairSetupSession = undefined;
        this.pairingVerified = false;
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

    private readonly clientInfo: ClientInfo;
    private readonly host: string;
    private readonly port: number;

    encryptionContext?: HAPEncryptionContext;

    private httpRequestResolver?: (value?: HTTPResponse | PromiseLike<HTTPResponse>) => void;

    constructor(hapClient: HAPClient) {
        super();
        this.parser = new HTTPResponseParser();

        this.clientInfo = hapClient.clientInfo;
        this.host = hapClient.host;
        this.port = hapClient.port;
    }

    ensureConnected(): Promise<void> {
        if (this.socket) {
            return Promise.resolve();
        }

        debugCon("Opening socket...");
        this.socket = net.createConnection(this.port, this.host);
        this.socket.on('close', this.handleClosed.bind(this));
        this.socket.on('data', this.handleIncomingData.bind(this));

        const promise = new Promise<void>(resolve => {
            this.socket!.on('connect', () => {
                debugCon("Successfully connected!");
                resolve();
            });
        });

        this.socket.setKeepAlive(true);
        this.socket.setNoDelay(true);

        return promise;
    }

    disconnect() {
        if (this.socket) {
            this.socket.end();
            // TODO mark destroyed
            // TODO do not handle incomming data
        }
    }

    private handleClosed() {
        this.socket = undefined;
        this.encryptionContext = undefined;
        this.httpRequestResolver = undefined;

        this.parser = new HTTPResponseParser(); // ensure parser buffer is cleared up

        debugCon("Disconnected!"); // TODO debug

        this.emit(HAPClientConnectionEvents.DISCONNECTED);
    }

    private handleIncomingData(data: Buffer) {
        if (this.encryptionContext) {
            data = encryption.layerDecrypt(data, this.encryptionContext); // TODO handle exception
        }

        this.parser.appendData(data);

        const messages: HTTPResponse[] = this.parser.parse();

        messages.forEach(message => {
            if (message.messageType === "EVENT") {
                console.log("RECEIVED EVENT");
                console.log(message);
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

    get(route: HTTPRoutes, queryParams: Record<string, string> = {}, headers: Record<string, string> = {}): Promise<HTTPResponse> {
        return this.sendRequest(HTTPMethod.GET, route, HTTPContentType.HAP_JSON, queryParams, headers);
    }

    put(route: HTTPRoutes, data: Buffer, queryParams: Record<string, string> = {}, headers: Record<string,string> = {}): Promise<HTTPResponse> {
        return this.sendRequest(HTTPMethod.PUT, route, HTTPContentType.HAP_JSON, queryParams, headers, data);
    }

    sendPairRequest(route: HTTPRoutes, data?: Buffer): Promise<HTTPResponse> {
        return this.sendRequest(HTTPMethod.POST, route, HTTPContentType.PAIRING_TLV8, {}, {}, data);
    }

    private sendRequest(method: HTTPMethod, route: HTTPRoutes, contentType: HTTPContentType,
                        queryParams: Record<string, string> = {}, headers: Record<string, string> = {}, data?: Buffer): Promise<HTTPResponse> {
        if (!this.socket) {
            return Promise.reject("Connection was not established!");
        }

        if (this.httpRequestResolver) {
            console.error("WARNING: http request still in progress");
            return Promise.reject("Request still in progress");
        }
        // TODO do we want to support hap-nodejs insecure pincode layer?

        headers["Content-Type"] = contentType;
        if (data && (method === HTTPMethod.POST || method === HTTPMethod.PUT)) {
            headers["Content-Length"] = data.length + "";
        } else {
            data = Buffer.alloc(0);
        }

        let query = "";
        Object.entries(queryParams).forEach(([key, value])=> {
            if (query.length) {
                query += ","
            }

            query += key + "=" + value
        });
        if (query) {
            query = "?" + query;
        }

        let request = Buffer.concat([
            Buffer.from(
                `${method} ${route + query} HTTP/1.1\r\n` +
                `Host: ${this.host}:${this.port}\r\n` +
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

}
