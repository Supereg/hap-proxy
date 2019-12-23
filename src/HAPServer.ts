import {HAPEncryptionContext, HAPStates, HAPStatusCode, PairMethods, TLVErrors, TLVValues} from "./HAPClient";
import net, {AddressInfo, Server, Socket} from "net";
import createDebug from 'debug';
import * as encryption from "./lib/crypto/encryption";
import {
    HTTPContentType,
    HTTPRequest,
    HTTPRequestParser,
    HTTPRoutes,
    HTTPServerResponse,
    HTTPStatus
} from "./lib/http-protocol";
import {EventEmitter} from "./lib/EventEmitter";
import srp from 'fast-srp-hap';
import * as crypto from "crypto";
import * as tlv from './lib/utils/tlv';
import * as hkdf from './lib/crypto/hkdf';
import tweetnacl from 'tweetnacl';
import {Advertiser} from "./lib/Advertiser";
import {AccessoryInfo, PairingInformation, PermissionTypes} from "./lib/storage/AccessoryInfo";

const debug = createDebug("HAPServer");
const debugCon = createDebug("HAPProxy");

export type ServerPairSetupSession = {
    connection: HAPServerConnection, // originator
    nextState: HAPStates,

    srpServer: srp.Server,
    sharedSecret: Buffer,
    sessionKey: Buffer,

    clientId: string,
    clientLTPK: Buffer,
}

export type ServerPairVerifySession = {
    nextState: HAPStates,

    // Curve25519KeyPair
    secretKey: Buffer,
    publicKey: Buffer,

    // received in M1
    clientPublicKey: Buffer,

    sharedSecret: Buffer,
    sessionKey: Buffer,
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

export class HAPServer {

    private accessoryInfo: AccessoryInfo;

    private tcpServer: Server;
    private connections: HAPServerConnection[] = [];

    private advertiser: Advertiser;

    private routeHandlers: Record<HTTPRoutes, HTTPRequestHandler> = {
        [HTTPRoutes.IDENTIFY]: this.handleIdentify.bind(this),
        [HTTPRoutes.PAIR_SETUP]: this.handlePair.bind(this),
        [HTTPRoutes.PAIR_VERIFY]: this.handlePairVerify.bind(this),
        [HTTPRoutes.PAIRINGS]: this.handlePairings.bind(this),
        [HTTPRoutes.ACCESSORIES]: NOT_FOUND_HANDLER,
        [HTTPRoutes.CHARACTERISTICS]: NOT_FOUND_HANDLER,
        [HTTPRoutes.PREPARE]: NOT_FOUND_HANDLER,
        [HTTPRoutes.RESOURCE]: NOT_FOUND_HANDLER,
    };

    private currentPairSetupSession?: Partial<ServerPairSetupSession>;

    constructor(accessoryInfo: AccessoryInfo) {
        this.accessoryInfo = accessoryInfo;

        this.tcpServer = net.createServer();
        this.tcpServer.on('listening', this.handleListening.bind(this));
        this.tcpServer.on('connection', this.handleConnection.bind(this));

        this.advertiser = new Advertiser(accessoryInfo);
    }

    listen(targetPort?: number) {
        this.tcpServer.listen(targetPort);
    }

    stop() {
        this.tcpServer.close(); // TODO close does not disconnect clients
        this.connections = []; // TODO ?
    }

    private handleListening() {
        const address = this.tcpServer.address();

        if (address && typeof address !== "string") {
            const port = address.port;
            debug("Server listening on port %s", port);

            this.advertiser.startAdvertising(port);
        }
    }

    private handleConnection(socket: Socket) {
        const connection = new HAPServerConnection(socket, this.routeHandlers);
        connection.on(HAPServerConnectionEvents.DISCONNECTED, this.handleConnectionClosed.bind(this, connection));

        this.connections.push(connection);

        debug("Received new connection on %s:%d!", connection.remoteAddress.address, connection.remoteAddress.port);
    }

    private handleConnectionClosed(connection: HAPServerConnection) {
        debug("Connection disconnected %s:%d!", connection.remoteAddress.address, connection.remoteAddress.port);

        const index = this.connections.indexOf(connection);
        if (index >= 0) {
            this.connections.splice(index, 1);
        }

        if (this.currentPairSetupSession && this.currentPairSetupSession.connection === connection) {
            this.currentPairSetupSession = undefined;
        }
    }

    // noinspection JSMethodCanBeStatic
    private handleIdentify(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        if (this.accessoryInfo.hasPairings()) {
            return Promise.resolve({
                status: 470, // TODO status
                contentType: HTTPContentType.HAP_JSON,
                data: Buffer.from(JSON.stringify({ status: HAPStatusCode.INSUFFICIENT_PRIVILEGES })),
            });
        }

        debug("**Unpaired Identify received**");

        return Promise.resolve({
            status: 204,
            contentType: HTTPContentType.HAP_JSON,
        });
    }

    private handlePair(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        if (this.accessoryInfo.hasPairings()) {
            return Promise.resolve({
                status: HTTPStatus.SUCCESS,
                contentType: HTTPContentType.PAIRING_TLV8,
                data: tlv.encode(TLVValues.STATE, HAPStates.M2, TLVValues.ERROR, TLVErrors.UNAVAILABLE),
            });
        }

        const data = tlv.decode(request.body);

        const state: HAPStates = data[TLVValues.STATE].readUInt8(0);

        if (this.currentPairSetupSession && this.currentPairSetupSession.connection !== connection) {
            return Promise.resolve({
                status: HTTPStatus.SUCCESS,
                contentType: HTTPContentType.PAIRING_TLV8,
                data: tlv.encode(TLVValues.STATE, HAPStates.M2, TLVValues.ERROR, TLVErrors.UNAVAILABLE),
            });
        }

        if (!this.currentPairSetupSession) {
            this.currentPairSetupSession = {
                connection: connection,
                nextState: HAPStates.M1, // expecting M1 as first state
            };
        }

        if (this.currentPairSetupSession && this.currentPairSetupSession.nextState !== state) {
            debug("Received /pair-setup with unexpected state!"); // TODO debug message
            return this.abortPairing(state + 1, TLVErrors.INVALID_REQUEST, HTTPStatus.BAD_REQUEST);
        }

        let partialPromise;
        if (state === HAPStates.M1) {
            partialPromise = this.handlePairM1(data);
        } else if (state === HAPStates.M3) {
            partialPromise = this.handlePairM3(data);
        } else if (state === HAPStates.M5) {
            partialPromise = this.handlePairM5(data);
        } else {
            return this.abortPairing(state + 1, TLVErrors.INVALID_REQUEST);
        }

        return partialPromise.then(partial => ({
            status: partial.status || HTTPStatus.SUCCESS,
            contentType: partial.contentType || HTTPContentType.PAIRING_TLV8,
            data: partial.data,
            headers: partial.headers,
        }));
    }

    private abortPairing(state: HAPStates, error: TLVErrors, status?: HTTPStatus): Promise<HTTPServerResponse> {
        this.currentPairSetupSession = undefined;
        return Promise.resolve({
            status: status || HTTPStatus.SUCCESS,
            contentType: HTTPContentType.PAIRING_TLV8,
            data: tlv.encode(TLVValues.STATE, state, TLVValues.ERROR, error),
        });
    }

    private handlePairM1(tlvData: Record<number, Buffer>): Promise<Partial<Partial<HTTPServerResponse>>> {
        debug("Received pair setup M1");

        const session = this.currentPairSetupSession!;

        const method: PairMethods = tlvData[TLVValues.METHOD].readUInt8(0); // TODO handle method
        // TODO pairings flags

        // step 1 - handled above
        // step 2 - not really useful for our scenario (render device unpairable after 100 failed pair attempts)
        // step 3 - handled above

        // step 4
        return new Promise<Partial<HTTPServerResponse>>((resolve, reject) => {
            srp.genKey(32, (error, key) => {
                if (session !== this.currentPairSetupSession) {
                    reject("pair session changed!");
                    return;
                }

                // step 5
                const username = Buffer.from("Pair-Setup");
                // step 6
                const salt = crypto.randomBytes(16);
                const srpParams = srp.params["3072"];

                // TODO handle pairing flags

                const pinBuf = Buffer.from(this.accessoryInfo.pincode);
                const srpServer = new srp.Server(srpParams, salt, username, pinBuf, key);
                session.srpServer = srpServer;
                // step 9
                const publicKey = srpServer.computeB();

                // step 10
                const response = tlv.encode(
                    TLVValues.STATE, HAPStates.M2,
                    TLVValues.PUBLIC_KEY, publicKey,
                    TLVValues.SALT, salt,
                    // TODO pairing flags?
                );

                session.nextState = HAPStates.M3; // we expect M3 for next request

                resolve({
                    data: response,
                });
            });
        });
    }

    private handlePairM3(tlvData: Record<number, Buffer>): Promise<Partial<Partial<HTTPServerResponse>>> {
        debug("Received pair setup M3");

        const session = this.currentPairSetupSession!;
        const srpServer = session.srpServer!;

        const publicKey = tlvData[TLVValues.PUBLIC_KEY];
        const clientProof = tlvData[TLVValues.PROOF];

        // step 1
        srpServer.setA(publicKey);
        session.sharedSecret = srpServer.computeK();

        // step 2
        try {
            srpServer.checkM1(clientProof);
        } catch (error) {
            // TODO debug
            return this.abortPairing(HAPStates.M4, TLVErrors.AUTHENTICATION);
        }

        // step 3
        const serverProof = srpServer.computeM2();

        session.nextState = HAPStates.M5;
        return Promise.resolve({
           data: tlv.encode(TLVValues.STATE, HAPStates.M4, TLVValues.PROOF, serverProof)
        });
    }

    private handlePairM5(tlvData: Record<number, Buffer>): Promise<Partial<HTTPServerResponse>> {
        debug("Received pair setup M5");

        const session = this.currentPairSetupSession!;

        // M5 Verification

        // step 1
        const encryptedDataContent = tlvData[TLVValues.ENCRYPTED_DATA];
        const encryptedData = encryptedDataContent.slice(0, -16);
        const authTag = encryptedDataContent.slice(-16);

        // step 2
        let salt = Buffer.from("Pair-Setup-Encrypt-Salt");
        let info = Buffer.from("Pair-Setup-Encrypt-Info");
        session.sessionKey = hkdf.HKDF("sha512", salt, session.sharedSecret!, info, 32);

        const plaintext = Buffer.alloc(encryptedData.length);
        const nonce = Buffer.from("PS-Msg05");

        if (!encryption.verifyAndDecrypt(session.sessionKey, nonce, encryptedData, authTag, null, plaintext)) {
            // TODO debug
            return this.abortPairing(HAPStates.M6, TLVErrors.AUTHENTICATION);
        }

        // step 3
        salt = Buffer.from("Pair-Setup-Controller-Sign-Salt");
        info = Buffer.from("Pair-Setup-Controller-Sign-Info");
        const iOSDeviceX = hkdf.HKDF("sha512", salt, session.sharedSecret!, info, 32);

        // step 4
        const subTLV = tlv.decode(plaintext);
        const iOSDevicePairingID = subTLV[TLVValues.IDENTIFIER];
        const iOSDeviceLTPK = subTLV[TLVValues.PUBLIC_KEY];
        const iOSDeviceSignature = subTLV[TLVValues.SIGNATURE];

        const iOSDeviceInfo = Buffer.concat([
            iOSDeviceX,
            iOSDevicePairingID,
            iOSDeviceLTPK,
        ]);

        // step 5
        if (!tweetnacl.sign.detached.verify(iOSDeviceInfo, iOSDeviceSignature, iOSDeviceLTPK)) {
            // TODO debug
            return this.abortPairing(HAPStates.M6, TLVErrors.AUTHENTICATION);
        }

        // step 6
        session.clientId = iOSDevicePairingID.toString();
        session.clientLTPK = iOSDeviceLTPK;

        return this.generatePairM5Response();
    }

    private generatePairM5Response(): Promise<Partial<HTTPServerResponse>> {
        debug("Sending pair setup M6");
        const session = this.currentPairSetupSession!;
        // step 1 (LT keys already generated)

        // step 2
        const salt = Buffer.from("Pair-Setup-Accessory-Sign-Salt");
        const info = Buffer.from("Pair-Setup-Accessory-Sign-Info");
        const accessoryX = hkdf.HKDF("sha512", salt, session.sharedSecret!, info, 32);

        // step 3
        const accessoryInfo = Buffer.concat([
           accessoryX,
           Buffer.from(this.accessoryInfo.accessoryId),
           this.accessoryInfo.longTermPublicKey,
        ]);

        // step 4
        const accessorySignature = tweetnacl.sign.detached(accessoryInfo, this.accessoryInfo.longTermSecretKey);

        // step 5
        const subTLV = tlv.encode(
            TLVValues.IDENTIFIER, this.accessoryInfo.accessoryId,
            TLVValues.PUBLIC_KEY, this.accessoryInfo.longTermPublicKey,
            TLVValues.SIGNATURE, accessorySignature,
        );

        // step 6
        const nonce = Buffer.from("PS-Msg06");
        const encryptedData = Buffer.alloc(subTLV.length);
        const authTag = Buffer.alloc(16);
        encryption.encryptAndSeal(session.sessionKey!, nonce, subTLV, null, encryptedData, authTag);

        // step 7
        const exchangeResponse = tlv.encode(
            TLVValues.STATE, HAPStates.M6,
            TLVValues.ENCRYPTED_DATA, Buffer.concat([encryptedData, authTag]),
        );

        // initial pairing is always the admin pairing
        this.accessoryInfo.addPairedClient(session.clientId!, session.clientLTPK!, PermissionTypes.ADMIN);

        this.currentPairSetupSession = undefined;

        this.advertiser.updateAdvertisement();

        debug("Successfully paired!"); // TODO debug message

        return this.accessoryInfo.save()
            .then(() => Promise.resolve({
                data: exchangeResponse,
            }));
    }

    private handlePairVerify(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        const data = tlv.decode(request.body);
        const state: HAPStates = data[TLVValues.STATE].readUInt8(0);

        if (!connection.pairVerifySession) {
            connection.pairVerifySession = {
                nextState: HAPStates.M1, // expecting M1 as first state
            };
        }

        if (connection.pairVerifySession.nextState !== state) {
            // probably received subsequent pair-verify, teardown old session
            connection.pairVerifySession = {
                nextState: HAPStates.M1, // expecting M1 as first state
            };
        }

        let partialPromise;
        if (state === HAPStates.M1) {
            partialPromise = this.handlePairVerifyM1(connection, data);
        } else if (state === HAPStates.M3) {
            partialPromise = this.handlePairVerifyM3(connection, data);
        } else {
            return this.abortPairVerify(connection, state + 1, TLVErrors.INVALID_REQUEST);
        }

        return partialPromise.then(partial => ({
            status: partial.status || HTTPStatus.SUCCESS,
            contentType: partial.contentType || HTTPContentType.PAIRING_TLV8,
            data: partial.data,
            headers: partial.headers,
        }));
    }

    // noinspection JSMethodCanBeStatic
    private abortPairVerify(connection: HAPServerConnection, state: HAPStates, error: TLVErrors, status?: HTTPStatus): Promise<HTTPServerResponse> {
        connection.pairVerifySession = undefined;
        return Promise.resolve({
            status: status || HTTPStatus.SUCCESS,
            contentType: HTTPContentType.PAIRING_TLV8,
            data: tlv.encode(TLVValues.STATE, state, TLVValues.ERROR, error),
        });
    }

    private handlePairVerifyM1(connection: HAPServerConnection, tlvData: Record<number, Buffer>): Promise<Partial<HTTPServerResponse>> {
        debug("Received pair verify M1"); // TODO specify
        const session = connection.pairVerifySession!;

        session.clientPublicKey = tlvData[TLVValues.PUBLIC_KEY];

        // step 1
        const keyPair = encryption.generateCurve25519KeyPair();
        session.publicKey = Buffer.from(keyPair.publicKey);
        session.secretKey = Buffer.from(keyPair.secretKey);

        // step 2
        session.sharedSecret = Buffer.from(encryption.generateCurve25519SharedSecKey(session.secretKey, session.clientPublicKey));

        // step 3
        const accessoryInfo = Buffer.concat([
            session.publicKey,
            Buffer.from(this.accessoryInfo.accessoryId),
            session.clientPublicKey,
        ]);

        // step 4
        const accessorySignature = tweetnacl.sign.detached(accessoryInfo, this.accessoryInfo.longTermSecretKey);

        // step 5
        const subTLV = tlv.encode(
            TLVValues.IDENTIFIER, this.accessoryInfo.accessoryId,
            TLVValues.SIGNATURE, accessorySignature,
        );

        // step 6
        const salt = Buffer.from("Pair-Verify-Encrypt-Salt");
        const info = Buffer.from("Pair-Verify-Encrypt-Info");
        session.sessionKey = hkdf.HKDF("sha512", salt, session.sharedSecret, info, 32);

        // step 7
        const nonce = Buffer.from("PV-Msg02");
        const encryptedData = Buffer.alloc(subTLV.length);
        const authTag = Buffer.alloc(16);
        encryption.encryptAndSeal(session.sessionKey, nonce, subTLV, null, encryptedData, authTag);

        // step 8
        const startResponse = tlv.encode(
            TLVValues.STATE, HAPStates.M2,
            TLVValues.PUBLIC_KEY, session.publicKey,
            TLVValues.ENCRYPTED_DATA, Buffer.concat([encryptedData, authTag]),
        );

        session.nextState = HAPStates.M3;

        return Promise.resolve({
            data: startResponse,
        });
    }

    private handlePairVerifyM3(connection: HAPServerConnection, tlvData: Record<number, Buffer>): Promise<Partial<HTTPServerResponse>> {
        debug("Received pair verify M3"); // TODO specify
        const session = connection.pairVerifySession!;

        // step 1 & 2
        const encryptedDataContent = tlvData[TLVValues.ENCRYPTED_DATA];
        const encryptedData = encryptedDataContent.slice(0, -16);
        const authTag = encryptedDataContent.slice(-16);
        const plaintext = Buffer.alloc(encryptedData.length);

        const nonce = Buffer.from("PV-Msg03");
        if (!encryption.verifyAndDecrypt(session.sessionKey!, nonce, encryptedData, authTag, null, plaintext)) {
            return this.abortPairVerify(connection, HAPStates.M4, TLVErrors.AUTHENTICATION);
        }

        // step 3
        const subTLV = tlv.decode(plaintext);
        const iOSDevicePairingID = subTLV[TLVValues.IDENTIFIER]; // aka clientId
        const iOSDeviceSignature = subTLV[TLVValues.SIGNATURE];

        const iOSDeviceLTPK = this.accessoryInfo.getClientPublicKey(iOSDevicePairingID.toString());

        if (!iOSDeviceLTPK) {
            // TODO debug client not paired attempted to pair-verify
            return this.abortPairVerify(connection, HAPStates.M4, TLVErrors.AUTHENTICATION);
        }

        // step 4
        const iOSDeviceInfo = Buffer.concat([
            session.clientPublicKey!,
            iOSDevicePairingID,
            session.publicKey!,
        ]);

        if (!tweetnacl.sign.detached.verify(iOSDeviceInfo, iOSDeviceSignature, iOSDeviceLTPK)) {
            // TODO debug: client provided invalid signature
            return this.abortPairVerify(connection, HAPStates.M4, TLVErrors.AUTHENTICATION);
        }

        // step 5

        // generate HAP encryption/decryption keys
        const salt = Buffer.from("Control-Salt");
        const accessoryToControllerInfo = Buffer.from("Control-Read-Encryption-Key");
        const controllerToAccessoryInfo = Buffer.from("Control-Write-Encryption-Key");

        const accessoryToControllerKey = hkdf.HKDF("sha512", salt, session.sharedSecret!, accessoryToControllerInfo, 32);
        const controllerToAccessoryKey = hkdf.HKDF("sha512", salt, session.sharedSecret!, controllerToAccessoryInfo, 32);

        connection.encryptionContext = new HAPEncryptionContext(session.sharedSecret!, accessoryToControllerKey, controllerToAccessoryKey);
        connection.pairingVerified = true;
        connection.clientId = iOSDevicePairingID.toString();
        connection.pairVerifySession = undefined;

        debug("Pairing verified"); // TODO debug message

        return Promise.resolve({
            data: tlv.encode(TLVValues.STATE, HAPStates.M4),
        });
    }

    private handlePairings(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        if (!connection.pairingVerified) {
            return Promise.resolve({
                status: 470, // TODO status
                contentType: HTTPContentType.HAP_JSON,
                data: Buffer.from(JSON.stringify({ status: HAPStatusCode.INSUFFICIENT_PRIVILEGES })),
            });
        }

        const tlvData = tlv.decode(request.body);

        const state = tlvData[TLVValues.STATE].readUInt8(0);
        const method = tlvData[TLVValues.METHOD].readUInt8(0);

        if (state !== HAPStates.M1) {
            return this.abortPairings(TLVErrors.INVALID_REQUEST);
        }

        let partialPromise;
        if (method === PairMethods.ADD_PAIRING) {
            partialPromise = this.addPairing(connection, tlvData);
        } else if (method === PairMethods.REMOVE_PAIRING) {
            partialPromise = this.removePairing(connection, tlvData);
        } else if (method === PairMethods.LIST_PAIRINGS) {
            partialPromise = this.listPairings(connection);
        } else {
            return this.abortPairings(TLVErrors.INVALID_REQUEST);
        }

        return partialPromise.then(partial => ({
            status: partial.status || HTTPStatus.SUCCESS,
            contentType: partial.contentType || HTTPContentType.PAIRING_TLV8,
            data: partial.data,
            headers: partial.headers,
        }));
    }

    // noinspection JSMethodCanBeStatic
    private abortPairings(error: TLVErrors, status?: HTTPStatus): Promise<HTTPServerResponse> {
        return Promise.resolve({
            status: status || HTTPStatus.SUCCESS,
            contentType: HTTPContentType.PAIRING_TLV8,
            data: tlv.encode(TLVValues.STATE, HAPStates.M2, TLVValues.ERROR, error),
        });
    }

    private addPairing(connection: HAPServerConnection, tlvData: Record<number, Buffer>): Promise<Partial<HTTPServerResponse>> {
        const clientId = tlvData[TLVValues.IDENTIFIER].toString();
        const publicKey = tlvData[TLVValues.PUBLIC_KEY];
        const permission: PermissionTypes = tlvData[TLVValues.PERMISSIONS].readUInt8(0);

        // step 2
        if (!this.accessoryInfo.hasAdminPermissions(clientId)) {
            return this.abortPairings(TLVErrors.AUTHENTICATION);
        }

        // step 3
        const clientPublicKey = this.accessoryInfo.getClientPublicKey(clientId);
        if (clientPublicKey) {
            // (a)
            if (clientPublicKey.toString("hex") !== publicKey.toString("hex")) {
                return this.abortPairings(TLVErrors.UNKNOWN);
            }

            // (b)
            this.accessoryInfo.updatePermission(clientId, permission);
        } else {
            // step 4
            this.accessoryInfo.addPairedClient(clientId, publicKey, permission);
        }

        // step 5
        // TODO log, additional pairing logged
        return this.accessoryInfo.save()
            .then(() => Promise.resolve({
                data: tlv.encode(TLVValues.STATE, HAPStates.M2),
            }));
    }

    private removePairing(connection: HAPServerConnection, tlvData: Record<number, Buffer>): Promise<Partial<HTTPServerResponse>> {
        const clientId = tlvData[TLVValues.IDENTIFIER].toString();

        // step 2
        if (!this.accessoryInfo.hasAdminPermissions(clientId)) {
            return this.abortPairings(TLVErrors.AUTHENTICATION);
        }

        // step 3
        this.accessoryInfo.removePairedClient(connection, clientId);

        if (!this.accessoryInfo.hasPairings()) {
            this.advertiser.updateAdvertisement();
        }

        // TODO log pairing removed
        return this.accessoryInfo.save()
            .then(() => Promise.resolve({
                data: tlv.encode(TLVValues.STATE, HAPStates.M2),
            }));
    }

    private listPairings(connection: HAPServerConnection): Promise<Partial<HTTPServerResponse>> {
        if (!this.accessoryInfo.hasAdminPermissions(connection.clientId!)) {
            return this.abortPairings(TLVErrors.AUTHENTICATION);
        }

        const pairings: PairingInformation[] = this.accessoryInfo.listPairings();

        const tlvList: any[] = [];
        pairings.forEach(pairing => {
            if (tlvList.length > 0) {
                tlvList.push(TLVValues.SEPARATOR, Buffer.alloc(0));
            }

            tlvList.push(
                TLVValues.IDENTIFIER, pairing.clientId,
                TLVValues.PUBLIC_KEY, pairing.publicKey,
                TLVValues.PERMISSIONS, pairing.permission,
            );
        });

        return Promise.resolve({
            data: tlv.encode(TLVValues.STATE, HAPStates.M2, ...tlvList),
        });
    }

    private handleAccessories(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        // TODO implement
        return NOT_FOUND_HANDLER(connection, request);
    }

    private handleCharacteristics(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        return NOT_FOUND_HANDLER(connection, request);
    }

    private handlePrepare(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        return NOT_FOUND_HANDLER(connection, request);
    }

    private handleResource(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        return NOT_FOUND_HANDLER(connection, request);
    }

}

export enum HAPServerConnectionEvents {
    DISCONNECTED = "disconnected",
}

export type HAPServerConnectionEventMap = {
    [HAPServerConnectionEvents.DISCONNECTED]: () => void;
}

export type HTTPRequestHandler = (connection: HAPServerConnection, request: HTTPRequest) => Promise<HTTPServerResponse>;

export const NOT_FOUND_HANDLER: HTTPRequestHandler = (connection, request) => {
    // TODO log connection name
    debugCon("Encountered 404 while accessing '%s'", request.uri);

    return Promise.resolve({
        status: HTTPStatus.NOT_FOUND,
        contentType: HTTPContentType.TEXT_HTML,
    });
};

export class HAPServerConnection extends EventEmitter<HAPServerConnectionEventMap> {

    private readonly socket: Socket;
    private readonly parser: HTTPRequestParser;

    private readonly routeHandler: Record<HTTPRoutes, HTTPRequestHandler>;

    remoteAddress: AddressInfo;

    pairVerifySession?: Partial<ServerPairVerifySession>;
    encryptionContext?: HAPEncryptionContext;

    clientId?: string;
    pairingVerified: boolean = false;

    private pendingEventData: Buffer = Buffer.alloc(0);

    private httpWorkingQueue: Promise<any> = Promise.resolve();

    constructor(socket: Socket, routeHandler: Record<HTTPRoutes, HTTPRequestHandler>) {
        super();
        this.socket = socket;
        this.socket.on('data', this.handleData.bind(this));
        this.socket.on('close', this.handleClose.bind(this));
        this.socket.on('error', this.handleError.bind(this));
        this.parser = new HTTPRequestParser();

        this.routeHandler = routeHandler;

        this.remoteAddress = this.socket.address() as AddressInfo;
        /* TODO gen some sessionID like hap-nodejs?
        this.sessionID = uuid.generate(clientSocket.remoteAddress + ':' + clientSocket.remotePort);
         */
    }

    private handleData(data: Buffer) {
        if (this.encryptionContext) {
            data = encryption.layerDecrypt(data, this.encryptionContext); // TODO handle exception
        }

        this.parser.appendData(data);

        const requests: HTTPRequest[] = this.parser.parse();

        requests.forEach(request => {
            const uri = request.uri;
            const requestHandler = this.routeHandler[uri as HTTPRoutes];

            console.log("Received http message"); // TODO remove
            console.log(request);
            this.httpWorkingQueue = this.httpWorkingQueue
                .then(() => requestHandler? requestHandler(this, request): NOT_FOUND_HANDLER(this, request))
                .catch(reason => {
                    debugCon("Encountered error when handling response: " + reason);
                    if (reason.stack) {
                        debugCon(reason.stack);
                    }

                    return Promise.resolve({ // TODO handle error reason
                        status: 500,
                        contentType: HTTPContentType.TEXT_HTML,
                        data: Buffer.from("Error occurred: " + reason),
                    })
                })
                .then(response => this.sendResponse(response));
        });
    }

    private sendResponse(response: HTTPServerResponse) {
        // TODO check if we are still connected

        console.log("Sending http response");
        console.log(response);

        const data = response.data || Buffer.alloc(0);

        const headers: Record<string, string> = response.headers || {};
        headers["Content-Type"] = response.contentType;
        headers["Content-Length"] = data.length + "";

        let responseBuf = Buffer.concat([
            Buffer.from(
                `HTTP/1.1 ${response.status} OK\r\n` +// TODO status name
                Object.keys(headers).reduce((acc: string, header: string) => {
                    return acc + `${header}: ${headers[header]}\r\n`;
                }, "") +
                `\r\n` // additional newline before content
            ),
            data
        ]);

        // with 'this.encryptionContext.decryptionNonce > 0' we ensure that we do not encrypt the
        // response of the last pair-verify response
        if (this.encryptionContext && this.encryptionContext.decryptionNonce > 0) {
            responseBuf = encryption.layerEncrypt(responseBuf, this.encryptionContext);
        }

        this.socket.write(responseBuf);
        /*
        return new Promise<HTTPResponse>(resolve => {
            this.httpRequestResolver = resolve;
            this.socket.write(response);
        });
         */
        /*
        if (this.httpRequestResolver) {
            console.error("WARNING: http request still in progress");
            return Promise.reject("Request still in progress");
        }
         */
    }

    private handleClose() {
        // TODO log + other stuff?
        this.emit(HAPServerConnectionEvents.DISCONNECTED);
        // TODO somehow interrupt currently active chain
    }

    private handleError(error: Error) {
        // TODO debug
    }


}
