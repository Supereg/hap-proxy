import {HAPEncryptionContext, HAPStates, HAPStatusCode, PairMethods, TLVErrors, TLVValues} from "./types/hap-proxy";
import net, {Server, Socket} from "net";
import createDebug from 'debug';
import * as encryption from "./crypto/encryption";
import {
    HTTPContentType,
    HTTPMethod,
    HTTPRequest,
    HTTPRequestParser,
    HTTPRoutes,
    HTTPServerResponse,
    HTTPStatus
} from "./lib/http-protocol";
import {EventEmitter} from "./lib/EventEmitter";
import * as crypto from "crypto";
import * as tlv from './utils/tlv';
import tweetnacl from 'tweetnacl';
import {Advertiser} from "./lib/Advertiser";
import {AccessoryInfo, AccessoryInfoEvents, PairingInformation, PermissionTypes} from "./storage/AccessoryInfo";
import {once} from "./utils/once";
import * as url from "url";
import {ParsedUrlQuery} from "querystring";
import {uuid} from "./utils/uuid";
import {SRP, SrpServer} from "fast-srp-hap";

const debug = createDebug("HAPServer");
const debugCon = createDebug("HAPProxy");

export type ServerPairSetupSession = {
    connection: HAPServerConnection, // originator
    nextState: HAPStates,

    srpServer: SrpServer,
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

export type HTTPServerResponseCallback = (error?: Error, response?: HTTPServerResponse) => void;

export enum HAPServerEvents {
    CONNECTION = "connection",
    ACCESSORIES = "accessories",
    GET_CHARACTERISTICS = "get-characteristics",
    SET_CHARACTERISTICS = "set-characteristics",
    PREPARE_WRITE = "prepare",
    RESOURCE = "resource",
    PAIRED = "paired",
    UNPAIRED = "unpaired",
}

export type HAPServerEventMap = {
    [HAPServerEvents.CONNECTION]: (connection: HAPServerConnection) => void;
    [HAPServerEvents.ACCESSORIES]: (connection: HAPServerConnection, callback: HTTPServerResponseCallback) => void;
    [HAPServerEvents.GET_CHARACTERISTICS]: (connection: HAPServerConnection, query: ParsedUrlQuery, callback: HTTPServerResponseCallback) => void;
    [HAPServerEvents.SET_CHARACTERISTICS]: (connection: HAPServerConnection, writeRequest: Buffer, callback: HTTPServerResponseCallback) => void;
    [HAPServerEvents.PREPARE_WRITE]: (connection: HAPServerConnection, prepareRequest: Buffer, callback: HTTPServerResponseCallback) => void;
    [HAPServerEvents.RESOURCE]: (connection: HAPServerConnection, resourceRequest: Buffer, callback: HTTPServerResponseCallback) => void;
    [HAPServerEvents.PAIRED]: () => void;
    [HAPServerEvents.UNPAIRED]: () => void;
}

export class HAPServer extends EventEmitter<HAPServerEventMap> {

    accessoryInfo: AccessoryInfo;

    private tcpServer: Server;
    private connections: HAPServerConnection[] = [];

    advertiser: Advertiser;

    private routeHandlers: Record<HTTPRoutes, HTTPRequestHandler> = {
        [HTTPRoutes.IDENTIFY]: this.handleIdentify.bind(this),
        [HTTPRoutes.PAIR_SETUP]: this.handlePair.bind(this),
        [HTTPRoutes.PAIR_VERIFY]: this.handlePairVerify.bind(this),
        [HTTPRoutes.PAIRINGS]: this.handlePairings.bind(this),
        [HTTPRoutes.ACCESSORIES]: this.handleAccessories.bind(this),
        [HTTPRoutes.CHARACTERISTICS]: this.handleCharacteristics.bind(this),
        [HTTPRoutes.PREPARE]: this.handlePrepare.bind(this),
        [HTTPRoutes.RESOURCE]: this.handleResource.bind(this),
    };

    private currentPairSetupSession?: Partial<ServerPairSetupSession>;

    constructor(accessoryInfo: AccessoryInfo) {
        super();
        this.accessoryInfo = accessoryInfo;
        this.accessoryInfo.on(AccessoryInfoEvents.REMOVED_CLIENT, this.handleClientUnpaired.bind(this));

        this.tcpServer = net.createServer();
        this.tcpServer.on('listening', this.handleListening.bind(this));
        this.tcpServer.on('connection', this.handleConnection.bind(this));

        this.advertiser = new Advertiser(accessoryInfo);
    }

    listen(targetPort?: number) {
        this.accessoryInfo.load() // transparently load AccessoryInfo from disk
            .then(() => debug("Loaded AccessoryInfo for '%s'", this.accessoryInfo.displayName))
            .then(() => this.tcpServer.listen(targetPort));
    }

    stop() {
        this.tcpServer.close();
        this.connections.forEach(connection => connection.disconnect());
    }

    private handleListening() {
        const address = this.tcpServer.address();

        if (address && typeof address !== "string") {
            const port = address.port;
            debug("Server listening on port %s", port);

            this.advertiser.createService(port);
            this.advertiser.startAdvertising();
        }
    }

    private handleConnection(socket: Socket) {
        const connection = new HAPServerConnection(socket, this.routeHandlers);
        connection.on(HAPServerConnectionEvents.DISCONNECTED, this.handleConnectionClosed.bind(this, connection));

        this.connections.push(connection);

        debug("Received new connection on %s!", connection.remoteAddress);

        this.emit(HAPServerEvents.CONNECTION, connection);
    }

    private handleConnectionClosed(connection: HAPServerConnection) {
        debug("Connection disconnected %s!", connection.remoteAddress);

        const index = this.connections.indexOf(connection);
        if (index >= 0) {
            this.connections.splice(index, 1);
        }

        if (this.currentPairSetupSession && this.currentPairSetupSession.connection === connection) {
            this.currentPairSetupSession = undefined;
        }
    }

    private handleClientUnpaired(initiator: HAPServerConnection, clientId: string) {
        this.connections.forEach(connection => {
            if (connection.clientId !== clientId) {
                return;
            }

            if (connection === initiator) {
                // the session which initiated the unpair removed it's own username, wait until the unpair request is finished
                // until we kill his connection
                connection.disconnectAfterWrite();
            } else {
                connection.disconnect();
            }
        });
    }

    // noinspection JSMethodCanBeStatic
    private handleIdentify(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        if (this.accessoryInfo.hasPairings()) { // if we are paired, a client cannot make an unpaired identify
            return Promise.resolve({
                status: 470, // TODO status
                contentType: HTTPContentType.HAP_JSON,
                data: Buffer.from(JSON.stringify({ status: HAPStatusCode.INSUFFICIENT_PRIVILEGES })),
            });
        }

        debug("**Unpaired Identify received**");
        // TODO we could potentially forward this but is this really necessary?

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
        return SRP.genKey(32).then(key => {
            if (session !== this.currentPairSetupSession) {
                throw new Error("pair session changed!");
            }

            // step 5
            const username = Buffer.from("Pair-Setup");
            // step 6
            const salt = crypto.randomBytes(16);
            const srpParams = SRP.params.hap;

            // TODO handle pairing flags

            session.srpServer = new SrpServer(srpParams, salt, username, Buffer.from(this.accessoryInfo.pincode), key);
            // step 9
            const publicKey = session.srpServer.computeB();

            // step 10
            const response = tlv.encode(
              TLVValues.STATE, HAPStates.M2,
              TLVValues.PUBLIC_KEY, publicKey,
              TLVValues.SALT, salt,
              // TODO pairing flags?
            );

            session.nextState = HAPStates.M3; // we expect M3 for next request

            return {
                data: response,
            };
        });
    }

    private handlePairM3(tlvData: Record<number, Buffer>): Promise<Partial<Partial<HTTPServerResponse>>> {
        debug("Received pair setup M3");

        const session = this.currentPairSetupSession!;
        const srpServer = session.srpServer!;

        const publicKey = tlvData[TLVValues.PUBLIC_KEY];
        const clientProof = tlvData[TLVValues.PASSWORD_PROOF];

        // step 1
        srpServer.setA(publicKey);
        session.sharedSecret = srpServer.computeK();

        // step 2
        try {
            srpServer.checkM1(clientProof);
        } catch (error) {
            console.warn("Rejected server pairing as incorrect pin code was supplied!");
            return this.abortPairing(HAPStates.M4, TLVErrors.AUTHENTICATION);
        }

        // step 3
        const serverProof = srpServer.computeM2();

        session.nextState = HAPStates.M5;
        return Promise.resolve({
           data: tlv.encode(TLVValues.STATE, HAPStates.M4, TLVValues.PASSWORD_PROOF, serverProof)
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
        session.sessionKey = encryption.HKDF("sha512", salt, session.sharedSecret!, info, 32);

        const nonce = Buffer.from("PS-Msg05");
        let plaintext;
        try {
            plaintext = encryption.chacha20_poly1305_decryptAndVerify(session.sessionKey, nonce, null, encryptedData, authTag);
        } catch (error) {
            // TODO debug
            return this.abortPairing(HAPStates.M6, TLVErrors.AUTHENTICATION);
        }

        // step 3
        salt = Buffer.from("Pair-Setup-Controller-Sign-Salt");
        info = Buffer.from("Pair-Setup-Controller-Sign-Info");
        const iOSDeviceX = encryption.HKDF("sha512", salt, session.sharedSecret!, info, 32);

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
        const accessoryX = encryption.HKDF("sha512", salt, session.sharedSecret!, info, 32);

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
        const encrypted = encryption.chacha20_poly1305_encryptAndSeal(session.sessionKey!, nonce, null, subTLV);

        // step 7
        const exchangeResponse = tlv.encode(
            TLVValues.STATE, HAPStates.M6,
            TLVValues.ENCRYPTED_DATA, Buffer.concat([encrypted.ciphertext, encrypted.authTag]),
        );

        // initial pairing is always the admin pairing
        this.accessoryInfo.addPairedClient(session.clientId!, session.clientLTPK!, PermissionTypes.ADMIN);

        this.currentPairSetupSession = undefined;

        this.advertiser.updateAdvertisement();

        debug("Successfully paired!"); // TODO debug message

        this.emit(HAPServerEvents.PAIRED);

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
        session.sessionKey = encryption.HKDF("sha512", salt, session.sharedSecret, info, 32);

        // step 7
        const nonce = Buffer.from("PV-Msg02");
        const encrypted = encryption.chacha20_poly1305_encryptAndSeal(session.sessionKey, nonce, null, subTLV);

        // step 8
        const startResponse = tlv.encode(
            TLVValues.STATE, HAPStates.M2,
            TLVValues.PUBLIC_KEY, session.publicKey,
            TLVValues.ENCRYPTED_DATA, Buffer.concat([encrypted.ciphertext, encrypted.authTag]),
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

        const nonce = Buffer.from("PV-Msg03");
        let plaintext;
        try {
            plaintext = encryption.chacha20_poly1305_decryptAndVerify(session.sessionKey!, nonce, null, encryptedData, authTag);
        } catch (error) {
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

        const accessoryToControllerKey = encryption.HKDF("sha512", salt, session.sharedSecret!, accessoryToControllerInfo, 32);
        const controllerToAccessoryKey = encryption.HKDF("sha512", salt, session.sharedSecret!, controllerToAccessoryInfo, 32);

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
        if (!this.accessoryInfo.hasAdminPermissions(connection.clientId!)) {
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
        if (!this.accessoryInfo.hasAdminPermissions(connection.clientId!)) {
            return this.abortPairings(TLVErrors.AUTHENTICATION);
        }

        // step 3
        this.accessoryInfo.removePairedClient(connection, clientId);

        if (!this.accessoryInfo.hasPairings()) {
            this.advertiser.updateAdvertisement();

            this.emit(HAPServerEvents.UNPAIRED);
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
        if (!connection.pairingVerified) {
            return Promise.resolve({
                status: 470, // TODO status
                contentType: HTTPContentType.HAP_JSON,
                data: Buffer.from(JSON.stringify({ status: HAPStatusCode.INSUFFICIENT_PRIVILEGES })),
            });
        }

        if (this.listenerCount(HAPServerEvents.ACCESSORIES) === 0) {
            return NOT_FOUND_HANDLER(connection, request); // TODO adjust response
        }

        return new Promise((resolve, reject) => {
            this.emit(HAPServerEvents.ACCESSORIES, connection, once((error: Error, response: HTTPServerResponse) => {
                if (error || !response) {
                    reject(error || new Error("Response was undefined!"));
                } else {
                    resolve(response);
                }
            }));
        });
    }

    private handleCharacteristics(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        if (!connection.pairingVerified) {
            return Promise.resolve({
                status: 470, // TODO status
                contentType: HTTPContentType.HAP_JSON,
                data: Buffer.from(JSON.stringify({ status: HAPStatusCode.INSUFFICIENT_PRIVILEGES })),
            });
        }

        if (request.method === HTTPMethod.GET) {
            if (this.listenerCount(HAPServerEvents.GET_CHARACTERISTICS) === 0) {
                return NOT_FOUND_HANDLER(connection, request); // TODO adjust response
            }

            const query = url.parse(request.uri, true).query;

            return new Promise<HTTPServerResponse>((resolve, reject) => {
               this.emit(HAPServerEvents.GET_CHARACTERISTICS, connection, query, once((error: Error, response: HTTPServerResponse) => {
                  if (error || !response) {
                      reject(error || new Error("Response was undefined!"));
                  } else {
                      resolve(response);
                  }
               }));
            });
        } else if (request.method === HTTPMethod.PUT) {
            if (this.listenerCount(HAPServerEvents.SET_CHARACTERISTICS) === 0) {
                return NOT_FOUND_HANDLER(connection, request); // TODO adjust response
            }

            return new Promise<HTTPServerResponse>((resolve, reject) => {
                this.emit(HAPServerEvents.SET_CHARACTERISTICS, connection, request.body, once((error: Error, response: HTTPServerResponse) => {
                    if (error || !response) {
                        reject(error || new Error("Response was undefined!"));
                    } else {
                        resolve(response);
                    }
                }));
            })
        } else {
            return Promise.reject();
            // TODO return appropriate error
        }
    }

    private handlePrepare(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        if (!connection.pairingVerified) {
            return Promise.resolve({
                status: 470, // TODO status
                contentType: HTTPContentType.HAP_JSON,
                data: Buffer.from(JSON.stringify({ status: HAPStatusCode.INSUFFICIENT_PRIVILEGES })),
            });
        }

        if (request.method == HTTPMethod.PUT) {
            if (this.listenerCount(HAPServerEvents.PREPARE_WRITE) === 0) {
                return NOT_FOUND_HANDLER(connection, request); // TODO adjust response
            }

            return new Promise<HTTPServerResponse>((resolve, reject) => {
               this.emit(HAPServerEvents.PREPARE_WRITE, connection, request.body, ((error: Error, response: HTTPServerResponse) => {
                   if (error || !response) {
                       reject(error || new Error("Response was undefined!"));
                   } else {
                       resolve(response);
                   }
               }));
            });
        } else {
            // TODO return appropriate error
            return Promise.reject();
        }
    }

    private handleResource(connection: HAPServerConnection, request: HTTPRequest): Promise<HTTPServerResponse> {
        if (!connection.pairingVerified) {
            return Promise.resolve({
                status: 470, // TODO status
                contentType: HTTPContentType.HAP_JSON,
                data: Buffer.from(JSON.stringify({ status: HAPStatusCode.INSUFFICIENT_PRIVILEGES })),
            });
        }

        if (request.method == HTTPMethod.POST) {
            if (this.listenerCount(HAPServerEvents.RESOURCE) === 0) {
                return NOT_FOUND_HANDLER(connection, request); // TODO adjust response
            }

            return new Promise<HTTPServerResponse>((resolve, reject) => {
                this.emit(HAPServerEvents.RESOURCE, connection, request.body, ((error: Error, response: HTTPServerResponse) => {
                    if (error || !response) {
                        reject(error || new Error("Response was undefined!"));
                    } else {
                        resolve(response);
                    }
                }));
            });
        } else {
            // TODO return appropriate error
            return Promise.reject();
        }
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

    sessionID: string;
    remoteAddress: string;

    pairVerifySession?: Partial<ServerPairVerifySession>;
    encryptionContext?: HAPEncryptionContext;

    clientId?: string;

    pairingVerified: boolean = false;
    private processingRequest: boolean = false;
    private disconnectAfterResponse: boolean = false;
    private socketClosed: boolean = false;

    private eventQueue: Buffer[] = []; // queue of unencrypted events

    private httpWorkingQueue: Promise<any> = Promise.resolve();

    constructor(socket: Socket, routeHandler: Record<HTTPRoutes, HTTPRequestHandler>) {
        super();
        this.socket = socket;
        this.socket.on('data', this.handleData.bind(this));
        this.socket.on('close', this.handleClose.bind(this));
        this.socket.on('error', this.handleError.bind(this));
        this.parser = new HTTPRequestParser();

        this.routeHandler = routeHandler;

        this.remoteAddress = this.socket.remoteAddress + ":" + this.socket.remotePort;
        this.sessionID = uuid.generate(this.remoteAddress);
        this.socket.setNoDelay(true);
        //this.socket.setKeepAlive(true);
    }

    disconnect() {
        if (this.socketClosed) {
            return;
        }

        this.pairingVerified = false;
        this.socketClosed = true;
        this.socket.end();
    }

    disconnectAfterWrite() {
        if (this.processingRequest) {
            this.disconnectAfterResponse = true;
        } else {
            this.disconnect();
        }
    }

    private handleData(data: Buffer) {
        if (this.socketClosed) {
            return;
        }

        if (this.processingRequest) { // TODO do we need this
            debugCon("Client tried sending http request while another request is still in progress");
            return;
        }
        this.processingRequest = true;

        if (this.encryptionContext) {
            try {
                data = encryption.layerDecrypt(data, this.encryptionContext);
            } catch (error) {
                this.disconnect();
                return;
            }
        }

        this.parser.appendData(data);

        const requests: HTTPRequest[] = this.parser.parse();

        requests.forEach(request => {
            const uri = request.uri;

            const route = uri.split("?")[0];
            const requestHandler = this.routeHandler[route as HTTPRoutes];

            this.httpWorkingQueue = this.httpWorkingQueue
                .then(() => requestHandler? requestHandler(this, request): NOT_FOUND_HANDLER(this, request))
                .catch(reason => {
                    debugCon("Encountered error when handling response: " + reason);
                    if (reason.stack) {
                        debugCon(reason.stack);
                    }

                    const response: HTTPServerResponse = {
                        status: 200,
                        contentType: this.pairingVerified
                            ? HTTPContentType.HAP_JSON
                            : HTTPContentType.PAIRING_TLV8,
                        data: this.pairingVerified
                            ? Buffer.from(JSON.stringify({
                                status: HAPStatusCode.SERVICE_COMMUNICATION_FAILURE,
                            }))
                            : tlv.encode(TLVValues.ERROR, TLVErrors.UNKNOWN),
                    };
                    return Promise.resolve(response)
                })
                .then(response => this.sendResponse(response));
        });
    }

    private sendResponse(response: HTTPServerResponse) {
        if (this.socketClosed) {
            throw new Error("Tried sending http response on a closed socket!");
        }

        const data = response.data || Buffer.alloc(0);

        const headers: Record<string, string> = response.headers || {};
        if (response.contentType && data.length > 0) {
            headers["Content-Type"] = response.contentType;
        }
        headers["Content-Length"] = data.length + "";

        let responseBuf = Buffer.concat([
            Buffer.from(
                `HTTP/1.1 ${response.status} OK\r\n` +// TODO status name
                Object.keys(headers).reduce((acc: string, header: string) => {
                    return acc + `${header}: ${headers[header]}\r\n`;
                }, "") +
                `\r\n` // additional newline before content
            ),
            data,
        ]);

        // with 'this.encryptionContext.decryptionNonce > 0' we ensure that we do not encrypt the
        // response of the last pair-verify response
        if (this.encryptionContext && this.encryptionContext.decryptionNonce > 0) {
            responseBuf = encryption.layerEncrypt(responseBuf, this.encryptionContext);
        }

        this.socket.write(responseBuf);

        this.processingRequest = false;
        this.flushEventQueue();

        if (this.disconnectAfterResponse) {
            this.disconnectAfterResponse = false;
            this.disconnect();
        }
    }

    sendRawEvent(data: Buffer) {
        let eventBuf = Buffer.concat([
            Buffer.from(
                `EVENT/1.0 200 OK\r\n` +
                `Content-Type: ${HTTPContentType.HAP_JSON}\r\n` +
                `Content-Length: ${data.length}\r\n` +
                `\r\n` // additional newline before content
            ),
            data,
        ]);

        if (this.processingRequest) {
            this.eventQueue.push(eventBuf);
        } else {
            if (this.encryptionContext) {
                eventBuf = encryption.layerEncrypt(eventBuf, this.encryptionContext);
            }

            this.socket.write(eventBuf);
        }
    }

    flushEventQueue() {
        if (this.eventQueue.length > 0) {
            debug("Flushing event queue");

            this.eventQueue.forEach(eventBuf => {
                if (this.encryptionContext) {
                    eventBuf = encryption.layerEncrypt(eventBuf, this.encryptionContext);
                }

                this.socket.write(eventBuf);
            });

            this.eventQueue = [];
        }
    }

    private handleClose() {
        // TODO log + other stuff?
        this.emit(HAPServerConnectionEvents.DISCONNECTED);
        // TODO somehow interrupt currently active chain
    }

    private handleError(error: Error) {
        console.log("Server client socket error:");
        console.log(error.stack);
        // TODO debug
    }


}
