import util from 'util';
import tweetnacl from 'tweetnacl';
import {StorageManager} from "./storage";

export class ClientInfo {

    readonly clientId: string;

    longTermPublicKey: Buffer = Buffer.alloc(0);
    longTermSecretKey: Buffer = Buffer.alloc(0);

    paired: boolean = false;
    accessoryIdentifier: string = "";
    accessoryLTPK: Buffer = Buffer.alloc(0); // currently we only support one pairing

    private constructor(clientId: string) {
        this.clientId = clientId;
    }

    async save() {
        const saved = {
            longTermPublicKey: this.longTermPublicKey.toString("hex"),
            longTermSecretKey: this.longTermSecretKey.toString("hex"),

            paired: this.paired,
            accessoryIdentifier: this.paired? this.accessoryIdentifier: undefined,
            accessoryLTPK: this.paired? this.accessoryLTPK.toString("hex"): undefined,
        };

        const storageKey = StorageManager.clientFormatPersistKey(this.clientId);
        await StorageManager.init();

        await StorageManager.setItem(storageKey, saved);
    }

    static async loadOrCreate(clientId: string) {
        const storageKey = StorageManager.clientFormatPersistKey(clientId);

        await StorageManager.init();
        const saved = await StorageManager.getItem(storageKey);

        if (saved) {
            const clientInfo = new ClientInfo(clientId);

            clientInfo.longTermPublicKey = Buffer.from(saved.longTermPublicKey, "hex");
            clientInfo.longTermSecretKey = Buffer.from(saved.longTermSecretKey, "hex");

            if (saved.paired) {
                clientInfo.paired = true;
                clientInfo.accessoryIdentifier = saved.accessoryIdentifier;
                clientInfo.accessoryLTPK = Buffer.from(saved.accessoryLTPK, "hex");
            }

            return clientInfo;
        } else {
            const clientInfo = new ClientInfo(clientId);

            const longTerm = tweetnacl.sign.keyPair();
            clientInfo.longTermPublicKey = Buffer.from(longTerm.publicKey);
            clientInfo.longTermSecretKey = Buffer.from(longTerm.secretKey);

            await clientInfo.save();

            return clientInfo;
        }
    }

}
