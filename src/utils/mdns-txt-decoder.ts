export namespace MDNSDecoder {

    let bytes = 0;
    let decodeBlockBytes = 0;

    // https://github.com/watson/dns-txt/pull/1/files
    export function decode(buf: Buffer, offset: number = 0, length: number = buf.length) {
        const oldOffset = offset;
        const data: Record<string, any> = {};

        while (offset < length) {
            offset += buf.readUInt8(offset) + 1;
        }

        if (offset !== length) {
            // non-RFC-6763 compliant format. Assume RFC-1464.
            bytes = length - oldOffset;
            return {
                [buf.slice(oldOffset, buf.indexOf('=', oldOffset)).toString()]: buf.slice(buf.indexOf('=', oldOffset) + 1).toString()
            };
        }

        offset = oldOffset;
        while (offset < length) {
            const b = decodeBlock(buf, offset);
            const i = buf.indexOf('=');
            offset += decodeBlockBytes;

            if (b.length === 0) {
                continue // ignore: most likely a single zero byte
            }

            if (i === -1) {
                data[b.toString().toLowerCase()] = true;
            } else if (i !== 0) {
                const key = b.slice(0, i).toString().toLowerCase();

                if (!(key in data)) { // overwriting not allowed
                    data[key] = b.slice(i + 1).toString();
                }
            }
        }

        bytes = offset - oldOffset;
        return data;
    }

    export function decodeBlock(buf: Buffer, offset: number) {
        const len = buf[offset];
        const to = offset + 1 + len;
        const b = buf.slice(offset + 1, to > buf.length ? buf.length : to);
        decodeBlockBytes = len + 1;
        return b
    }

}
