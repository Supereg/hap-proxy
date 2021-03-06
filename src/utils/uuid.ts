import crypto, { BinaryLike } from 'crypto';

export namespace uuid {
    export const BASE_UUID = '-0000-1000-8000-0026BB765291';

    const VALID_UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/i;
    const SHORT_FORM_REGEX = /^0*([0-9a-f]{1,8})-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;
    const VALID_SHORT_REGEX = /^[0-9a-f]{1,8}$/i;

    // http://stackoverflow.com/a/25951500/66673
    export function generate(data: BinaryLike) {
        const sha1sum = crypto.createHash('sha1');
        sha1sum.update(data);
        const s = sha1sum.digest('hex');
        let i = -1;
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c: string) => {
            i += 1;
            switch (c) {
                case 'y':
                    return ((parseInt('0x' + s[i], 16) & 0x3) | 0x8).toString(16);
                case 'x':
                default:
                    return s[i];
            }
        });
    }

    export function isValid(UUID: string) {
        return VALID_UUID_REGEX.test(UUID);
    }

    // https://github.com/defunctzombie/node-uuid/blob/master/uuid.js
    export function unparse(buf: Buffer | string, offset: number = 0) {
        let i = offset;
        return buf[i++].toString(16) + buf[i++].toString(16) +
            buf[i++].toString(16) + buf[i++].toString(16) + '-' +
            buf[i++].toString(16) + buf[i++].toString(16) + '-' +
            buf[i++].toString(16) + buf[i++].toString(16) + '-' +
            buf[i++].toString(16) + buf[i++].toString(16) + '-' +
            buf[i++].toString(16) + buf[i++].toString(16) +
            buf[i++].toString(16) + buf[i++].toString(16) +
            buf[i++].toString(16) + buf[i++].toString(16);
    }

    export function write(uuid: string, buf: Buffer, offset: number = 0) {
        uuid = uuid.replace(/-/g, "");

        for (let i = 0; i < uuid.length; i += 2) {
            const octet = uuid.substring(i, i + 2);
            buf.write(octet, offset++, "hex");
        }
    }

    export function toShortForm(uuid: string, base: string = BASE_UUID) {
        if (!isValid(uuid)) throw new TypeError('uuid was not a valid UUID or short form UUID');
        if (base && !isValid('00000000' + base)) throw new TypeError('base was not a valid base UUID');
        if (base && !uuid.endsWith(base)) return uuid.toUpperCase();

        return uuid.replace(SHORT_FORM_REGEX, '$1').toUpperCase();
    }

    export function toLongForm(uuid: string, base: string = BASE_UUID) {
        if (isValid(uuid)) return uuid.toUpperCase();
        if (!VALID_SHORT_REGEX.test(uuid)) throw new TypeError('uuid was not a valid UUID or short form UUID (' + uuid + ')');
        if (!isValid('00000000' + base)) throw new TypeError('base was not a valid base UUID');

        return (('00000000' + uuid).substr(-8) + base).toUpperCase();
    }

}
