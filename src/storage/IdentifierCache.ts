import {StorageManager} from "./storage";
import {ClientInfo} from "./ClientInfo";

export interface TypeEntry {
    serviceType: string,
    characteristicType: string;
}

export interface IdentifierCacheEntry {
    aid: number,
    serviceIid: number,
    characteristicIid: number,
    serviceType: string,
    characteristicType: string,
}

// mapping of 'accessoryId.instanceId' to characteristics type (aka uuid)
export class IdentifierCache {

    private readonly clientInfo: ClientInfo;

    private typeCache: Record<string, TypeEntry> = {}; // indexed by "aid.iid" (iid of the characteristic)
    private serviceIidCache: Record<string, number> = {}; // indexed by "aid.iid" (iid of the characteristic); value is iid of the service

    private loaded = false;

    constructor(clientInfo: ClientInfo) {
        this.clientInfo = clientInfo;
    }

    rebuild() {
        this.typeCache = {};
    }

    persists(aid: number, serviceIid: number, characteristicIid: number, serviceType: string, characteristicType: string) {
        this.typeCache[aid + "." + characteristicIid] = {
            serviceType: serviceType,
            characteristicType: characteristicType,
        };

        this.serviceIidCache[aid + "." + characteristicIid] = serviceIid;
    }

    entries(): IdentifierCacheEntry[] {
        return Object.entries(this.typeCache).map(([id, types]) => {
            const [aid, iid] = id.split("|");
            const serviceIid = this.serviceIidCache[id];

            return {
                aid: parseInt(aid),
                serviceIid: serviceIid,
                characteristicIid: parseInt(iid),
                serviceType: types.serviceType,
                characteristicType: types.characteristicType,
            };
        });
    }

    /**
     * Lookup of the service and characteristic types for the given ids
     *
     * @param aid {number} - accessory id
     * @param iid {number} - instance id of the characteristic
     */
    lookupType(aid: number, iid: number): TypeEntry {
        return this.typeCache[aid + "." + iid];
    }

    /**
     * Lookup of the iid of the service for the given ids
     *
     * @param aid {number} - accessory id
     * @param iid {number} - instance id of the characteristic
     */
    lookupServiceIid(aid: number, iid: number): number {
        return this.serviceIidCache[aid + "." + iid];
    }

    async save() {
        if (!this.loaded) {
            throw new Error("Tried saving ClientInfo before it was even loaded!");
        }

        await this.clientInfo.load();
        const storageKey = StorageManager.identifierCacheFormatPersistKey(this.clientInfo.clientId);
        await StorageManager.init();

        const saved = {
            typeCache: this.typeCache,
            serviceIidCache: this.serviceIidCache,
        };

        await StorageManager.setItem(storageKey, saved);
    }

    async load() {
        await this.clientInfo.load();
        const storageKey = StorageManager.identifierCacheFormatPersistKey(this.clientInfo.clientId);

        await StorageManager.init();
        const saved = await StorageManager.getItem(storageKey);

        this.loaded = true;

        if (saved) {
            this.typeCache = saved.typeCache || {};
            this.serviceIidCache = saved.serviceIidCache || {};
        } else {
            await this.save();
        }
    }

}
