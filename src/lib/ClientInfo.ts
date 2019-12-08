import storage from 'node-persist';
import util from 'util';
import tweetnacl from 'tweetnacl';

export class ClientInfo {

    private static storageInit: boolean = false;

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

        const storageKey = ClientInfo.formatPersistKey(this.clientId);
        await ClientInfo.init();

        await storage.setItem(storageKey, saved);
    }

    static async loadOrCreate(clientId: string) {
        const storageKey = ClientInfo.formatPersistKey(clientId);

        await ClientInfo.init();
        const saved = await storage.getItem(storageKey);

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

            return clientInfo;
        }
    }

    static formatPersistKey(clientId: string) {
        return util.format("ClientInfo.%s.json", clientId.toUpperCase());
    }

    static async init() {
        if (!this.storageInit) {
            this.storageInit = true;
            await storage.init(); // TODO storage path?
        }
    }

}
