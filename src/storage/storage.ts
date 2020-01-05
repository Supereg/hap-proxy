import storage, {DatumOptions, WriteFileResult} from 'node-persist';
import util from "util";

let storageInit = false;

export namespace StorageManager {

    let initPromise: Promise<any> = Promise.resolve();

    export async function init() {
        if (!storageInit) {
            storageInit = true;
            initPromise = initPromise.then(() => storage.init()); // TODO storage path
        }

        await initPromise;
    }

    export function getItem(key: string): Promise<any> {
        return storage.getItem(key);
    }

    export function setItem(key: string, value: any, options?: DatumOptions): Promise<WriteFileResult> {
        return storage.setItem(key, value, options);
    }

    export function clientFormatPersistKey(clientId: string) {
        return util.format("ClientInfo.%s.json", clientId.toUpperCase());
    }

    export function identifierCacheFormatPersistKey(clientId: string) {
        return util.format("IdentifierCache.%s.json", clientId.toUpperCase());
    }

    export function accessoryFormatPersistKey(accessoryName: string) {
        return util.format("AccessoryInfo.%s.json", accessoryName.toUpperCase());
    }

}
