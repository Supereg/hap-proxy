import {StorageManager} from "./storage";
import tweetnacl from "tweetnacl";
import crypto from "crypto";
import {HAPServerConnection} from "../../HAPServer";
import {SetupCodeGenerator} from "../setup-code";
import {HAPAccessoryCategory} from "../../types/hap-proxy";

export enum PermissionTypes {
    USER = 0x00,
    ADMIN = 0x01, // admins are the only ones who can add/remove/list pairings (also some characteristics are restricted)
}

export type PairingInformation = {
    clientId: string,
    publicKey: Buffer,
    permission: PermissionTypes,
}

export type SavedPairingInformation = {
    clientId: string,
    publicKey: string,
    permission: PermissionTypes,
}

export class AccessoryInfo {

    private readonly accessoryName: string;
    readonly accessoryId: string;
    displayName: string = ""; // TODO do we need that?
    category: HAPAccessoryCategory = HAPAccessoryCategory.OTHER; // TODO do we need that?

    pincode: string = "";

    longTermPublicKey: Buffer = Buffer.alloc(0);
    longTermSecretKey: Buffer = Buffer.alloc(0);

    pairedClients: Record<string, PairingInformation> = {};
    private pairedAdminClientCount: number = 0;

    configVersion: number = 1;
    // configHash: string = ""; hash created by HAP-NodeJS to check whether to increment the configVersion or not
    setupID: string = "";

    private constructor(accessoryName: string, accessoryId: string) {
        this.accessoryName = accessoryName;
        this.accessoryId = accessoryId;
    }

    /**
     * Add a paired client to memory.
     * @param {string} clientId
     * @param {Buffer} publicKey
     * @param {PermissionTypes} permission
     */
    addPairedClient = (clientId: string, publicKey: Buffer, permission: PermissionTypes) => {
        this.pairedClients[clientId] = {
            clientId: clientId,
            publicKey: publicKey,
            permission: permission
        };

        if (permission === PermissionTypes.ADMIN)
            this.pairedAdminClientCount++;
    };

    updatePermission = (username: string, permission: PermissionTypes) => {
        const pairingInformation = this.pairedClients[username];

        if (pairingInformation) {
            const oldPermission = pairingInformation.permission;
            pairingInformation.permission = permission;

            if (oldPermission === PermissionTypes.ADMIN && permission !== PermissionTypes.ADMIN) {
                this.pairedAdminClientCount--;
            } else if (oldPermission !== PermissionTypes.ADMIN && permission === PermissionTypes.ADMIN) {
                this.pairedAdminClientCount++;
            }
        }
    };

    listPairings = () => {
        const array = [] as PairingInformation[];

        for (const clientId in this.pairedClients) {
            // noinspection JSUnfilteredForInLoop
            const pairingInformation = this.pairedClients[clientId] as PairingInformation;
            array.push(pairingInformation);
        }

        return array;
    };

    /**
     * Remove a paired client from memory.
     * @param controller - the session of the controller initiated the removal of the pairing
     * @param {string} clientId
     */
    removePairedClient = (controller: HAPServerConnection, clientId: string) => {
        this._removePairedClient0(controller, clientId);

        if (this.pairedAdminClientCount === 0) { // if we don't have any admin clients left paired it is required to kill all normal clients
            for (const clientId0 in this.pairedClients) {
                // noinspection JSUnfilteredForInLoop
                this._removePairedClient0(controller, clientId0);
            }
        }
    };

    _removePairedClient0 = (controller: HAPServerConnection, clientId: string) => {
        if (this.pairedClients[clientId] && this.pairedClients[clientId].permission === PermissionTypes.ADMIN)
            this.pairedAdminClientCount--;
        delete this.pairedClients[clientId];

        // TODO Session.destroyExistingConnectionsAfterUnpair(controller, clientId);
    };

    /**
     * Check if clientId is paired
     * @param username
     */
    isPaired = (username: string) => {
        return !!this.pairedClients[username];
    };

    hasAdminPermissions = (clientId: string) => {
        if (!clientId) return false;
        const pairingInformation = this.pairedClients[clientId];
        return !!pairingInformation && pairingInformation.permission === PermissionTypes.ADMIN;
    };

    hasPairings() {
        //return Object.keys(this.pairedClients).length > 0;
        // we have at least one admin controller if we have any paired clients; should be easier to calculate
        return this.pairedAdminClientCount > 0;
    }

// Gets the public key for a paired client as a Buffer, or falsey value if not paired.
    getClientPublicKey = (clientId: string) => {
        const pairingInformation = this.pairedClients[clientId];
        if (pairingInformation) {
            return pairingInformation.publicKey;
        } else {
            return undefined;
        }
    };

    async save() {
        const saved = {
            accessoryId: this.accessoryId,
            displayName: this.displayName,
            category: this.category,

            pincode: this.pincode,

            longTermPublicKey: this.longTermPublicKey.toString("hex"),
            longTermSecretKey: this.longTermSecretKey.toString("hex"),

            pairedClients: [],

            configVersion: this.configVersion,
            setupID: this.setupID,
        };

        for (const clientId in this.pairedClients) {
            // noinspection JSUnfilteredForInLoop
            const pairing: PairingInformation = this.pairedClients[clientId];

            // noinspection JSUnfilteredForInLoop
            const savedPairing: SavedPairingInformation = {
                clientId: clientId,
                publicKey: pairing.publicKey.toString("hex"),
                permission: pairing.permission,
            };

            // @ts-ignore
            saved.pairedClients.push(savedPairing);
        }

        const storageKey = StorageManager.accessorFormatPersistKey(this.accessoryName);
        await StorageManager.init();

        await StorageManager.setItem(storageKey, saved);
    }

    static async loadOrCreate(accessoryName: string, category: HAPAccessoryCategory, pincode?: string) {
        const storageKey = StorageManager.accessorFormatPersistKey(accessoryName);

        await StorageManager.init();
        const saved = await StorageManager.getItem(storageKey);

        if (saved) {
            const accessoryId = saved.accessoryId;

            const accessoryInfo = new AccessoryInfo(accessoryName, accessoryId);

            accessoryInfo.displayName = saved.displayName;
            accessoryInfo.category = saved.category;

            accessoryInfo.pincode = saved.pincode;

            accessoryInfo.longTermPublicKey = Buffer.from(saved.longTermPublicKey, "hex");
            accessoryInfo.longTermSecretKey = Buffer.from(saved.longTermSecretKey, "hex");

            accessoryInfo.configVersion = saved.configVersion;
            accessoryInfo.setupID = saved.setupID;

            const pairings: SavedPairingInformation[] = saved.pairedClients;
            pairings.forEach(savedPairing => {
                const pairingInformation: PairingInformation = {
                    clientId: savedPairing.clientId,
                    publicKey: Buffer.from(savedPairing.publicKey, "hex"),
                    permission: savedPairing.permission,
                };

                accessoryInfo.pairedClients[savedPairing.clientId] = pairingInformation;
                if (pairingInformation.permission === PermissionTypes.ADMIN) {
                    accessoryInfo.pairedAdminClientCount++;
                }
            });

            return accessoryInfo;
        } else {
            const accessoryId = this.genRandomMac();
            const accessoryInfo = new AccessoryInfo(accessoryName, accessoryId);

            // we need to create a network unique displayName
            accessoryInfo.displayName = accessoryName + " "
                + crypto.createHash("sha512")
                    .update(accessoryId, 'utf8')
                    .digest("hex").slice(0, 4).toUpperCase();
            accessoryInfo.category = category;
            accessoryInfo.pincode = pincode || await SetupCodeGenerator.generate();
            if (!pincode) {
                // TODO do we have a nice way for this?
                console.log("Generated setup code: " + accessoryInfo.pincode);
            }

            const longTerm = tweetnacl.sign.keyPair(); // generate new lt key pair
            accessoryInfo.longTermPublicKey = Buffer.from(longTerm.publicKey);
            accessoryInfo.longTermSecretKey = Buffer.from(longTerm.secretKey);

            accessoryInfo.setupID = this.generateSetupID();

            await accessoryInfo.save();

            return accessoryInfo;
        }
    }

    private static genRandomMac() {
        const buf = crypto.randomBytes(6);

        let output = "";
        for (let i = 0; i < 6; i++) {
            if (output.length > 0) {
                output += ":";
            }

            output += buf.toString("hex", i, i+1).toUpperCase();
        }

        return output;
    }

    private static generateSetupID = () => { // should persist over factory resets, but isn't really doable for us
        const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const bytes = crypto.randomBytes(4);
        let setupID = '';

        for (var i = 0; i < 4; i++) {
            var index = bytes.readUInt8(i) % 26;
            setupID += chars.charAt(index);
        }

        return setupID;
    }

}
