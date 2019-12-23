import storage, {DatumOptions, WriteFileResult} from 'node-persist';
import util from "util";

let storageInit = false;

export namespace StorageManager {

    export async function init() {
        if (!storageInit) {
            storageInit = true;
            await storage.init(); // TODO storage path
        }
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

    export function accessorFormatPersistKey(accessoryId: string) {
        return util.format("AccessoryInfo.%s.json", accessoryId.toUpperCase());
    }

}
