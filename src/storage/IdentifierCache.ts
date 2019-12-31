import {StorageManager} from "./storage";

export interface IdentifierCacheEntry {
    serviceType: string,
    characteristicType: string;
}

// mapping of 'accessoryId.instanceId' to characteristics type (aka uuid)
export class IdentifierCache {

    private readonly clientId: string;

    private typeCache: Record<string, IdentifierCacheEntry> = {}; // indexed by "aid.iid" (iid of the characteristic)
    private serviceIidCache: Record<string, number> = {}; // indexed by "aid.iid" (iid of the characteristic); value is iid of the service

    constructor(clientId: string) {
        this.clientId = clientId;
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

    /**
     * Lookup of the service and characteristic types for the given ids
     *
     * @param aid {number} - accessory id
     * @param iid {number} - instance id of the characteristic
     */
    lookupType(aid: number, iid: number): IdentifierCacheEntry {
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
        const storageKey = StorageManager.identifierCacheFormatPersistKey(this.clientId);
        await StorageManager.init();

        const saved = {
            typeCache: this.typeCache,
            serviceIidCache: this.serviceIidCache,
        };

        await StorageManager.setItem(storageKey, saved);
    }

    static async loadOrCreate(clientId: string) {
        const storageKey = StorageManager.clientFormatPersistKey(clientId);

        await StorageManager.init();
        const saved = await StorageManager.getItem(storageKey);

        const identifierCache = new IdentifierCache(clientId);
        if (saved) {
            identifierCache.typeCache = saved.typeCache || {};
            identifierCache.serviceIidCache = saved.serviceIidCache || {};
        } else {
            await identifierCache.save();
        }

        return identifierCache;
    }

}
