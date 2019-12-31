import {StorageManager} from "./storage";

export interface IdentifierCacheEntry {
    serviceType: string,
    characteristicType: string;
}

// mapping of 'accessoryId.instanceId' to characteristics type (aka uuid)
export class IdentifierCache {

    private readonly clientId: string;
    private cache: Record<string, IdentifierCacheEntry> = {};

    constructor(clientId: string) {
        this.clientId = clientId;
    }

    rebuild() {
        this.cache = {};
    }

    persists(aid: number, iid: number, serviceType: string, characteristicType: string) {
        this.cache[aid + "." + iid] = {
            serviceType: serviceType,
            characteristicType: characteristicType,
        };
    }

    lookup(aid: number, iid: number): IdentifierCacheEntry {
        return this.cache[aid + "." + iid];
    }

    async save() {
        const storageKey = StorageManager.identifierCacheFormatPersistKey(this.clientId);
        await StorageManager.init();

        await StorageManager.setItem(storageKey, this.cache);
    }

    static async loadOrCreate(clientId: string) {
        const storageKey = StorageManager.clientFormatPersistKey(clientId);

        await StorageManager.init();
        const saved = await StorageManager.getItem(storageKey);

        const identifierCache = new IdentifierCache(clientId);
        if (saved) {
            identifierCache.cache = saved;
        } else {
            await identifierCache.save();
        }

        return identifierCache;
    }

}
