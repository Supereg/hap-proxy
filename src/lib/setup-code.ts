import crypto from 'crypto';

export namespace SetupCodeGenerator {

    const invalid = [
        '000-00-000',
        '111-11-111',
        '222-22-222',
        '333-33-333',
        '444-44-444',
        '555-55-555',
        '666-66-666',
        '777-77-777',
        '888-88-888',
        '999-99-999',
        '123-45-678',
        '876-54-321',
    ];

    export function generate(): Promise<string> {
        return new Promise(((resolve, reject) => {
            crypto.randomBytes(6, (error, buffer) => {
                if (error) {
                    return reject(error);
                }

                const setupCode = toString(buffer);
                if (invalid.includes(setupCode)) {
                    resolve(generate());
                } else {
                    resolve(setupCode);
                }
            });
        }))
    }

    function toString(buffer: Buffer) {
        return ('000' + buffer.readUInt16LE(0)).substr(-3) + '-' +
            ('00' + buffer.readUInt16LE(2)).substr(-2) + '-' +
            ('000' + buffer.readUInt16LE(4)).substr(-3);
    }

}
