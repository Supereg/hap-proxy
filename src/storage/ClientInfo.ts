import tweetnacl from 'tweetnacl';
import {StorageManager} from "./storage";
import {PinProvider} from "../HAPClient";
import {uuid} from "../utils/uuid";
import * as crypto from "crypto";

export class ClientInfo {

    readonly accessoryName: string;
    clientId: string = "";
    private readonly pinProvider: string | PinProvider;

    longTermPublicKey: Buffer = Buffer.alloc(0);
    longTermSecretKey: Buffer = Buffer.alloc(0);

    paired: boolean = false;
    accessoryIdentifier: string = "";
    accessoryLTPK: Buffer = Buffer.alloc(0); // currently we only support one pairing

    private loaded: boolean = false;

    constructor(accessoryName: string, pinProvider: string | PinProvider) {
        this.accessoryName = accessoryName;
        this.pinProvider = pinProvider;
    }

    pincode(): Promise<string> {
        if (typeof this.pinProvider === "string") {
            return Promise.resolve(this.pinProvider);
        } else {
            const callable: PinProvider = this.pinProvider;
            return new Promise<string>(resolve => callable(pinCode => resolve(pinCode)));
        }
    }

    async save() {
        if (!this.loaded) {
            throw new Error("Tried saving ClientInfo before it was even loaded!");
        }

        const saved = {
            clientId: this.clientId,

            longTermPublicKey: this.longTermPublicKey.toString("hex"),
            longTermSecretKey: this.longTermSecretKey.toString("hex"),

            paired: this.paired,
            accessoryIdentifier: this.paired? this.accessoryIdentifier: undefined,
            accessoryLTPK: this.paired? this.accessoryLTPK.toString("hex"): undefined,
        };

        const storageKey = StorageManager.clientFormatPersistKey(this.accessoryName);
        await StorageManager.init();

        await StorageManager.setItem(storageKey, saved);
    }

    async load() {
        if (this.loaded) {
            return Promise.resolve();
        }

        const storageKey = StorageManager.clientFormatPersistKey(this.accessoryName);

        await StorageManager.init();
        const saved = await StorageManager.getItem(storageKey);

        this.loaded = true;

        if (saved) {
            this.clientId = saved.clientId;

            this.longTermPublicKey = Buffer.from(saved.longTermPublicKey, "hex");
            this.longTermSecretKey = Buffer.from(saved.longTermSecretKey, "hex");

            if (saved.paired) {
                this.paired = true;
                this.accessoryIdentifier = saved.accessoryIdentifier;
                this.accessoryLTPK = Buffer.from(saved.accessoryLTPK, "hex");
            }
        } else {
            this.clientId = uuid.generate(crypto.randomBytes(4)).toUpperCase(); // generate random clientId

            const longTerm = tweetnacl.sign.keyPair();
            this.longTermPublicKey = Buffer.from(longTerm.publicKey);
            this.longTermSecretKey = Buffer.from(longTerm.secretKey);

            await this.save();
        }
    }

}
