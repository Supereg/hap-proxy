declare module 'bonjour-hap' {

    export enum Protocols {
        TCP = 'tcp',
        UDP = 'udp',
    }

    export type Nullable<T> = T | null;
    export type TxtRecord = Record<string, string>;

    export class Service {
        name: string;
        type: string;
        subtypes: Nullable<string[]>;
        protocol: Protocols;
        host: string;
        port: number;
        fqdn: string;
        txt: Nullable<Record<string, any>>;
        rawTxt: Buffer[];
        published: boolean;

        start(): void;
        stop(callback?: () => void): void;
        destroy(): void;
        updateTxt(txt: TxtRecord): void;
    }

    export type ServiceCallback = (service: Service) => void;

    export class Browser {
        services: Service[];

        on(event: 'up', callback: ServiceCallback): this;
        on(event: 'down', callback: ServiceCallback): this

        start(): void;
        stop(): void;
        update(): void;
    }

    export type PublishOptions = {
        category?: any,
        host?: string;
        name?: string;
        pincode?: string;
        port: number;
        protocol?: Protocols;
        subtypes?: string[];
        txt?: Record<string, string>;
        type?: string;
        username?: string;
    };

    export type BrowsingOptions = {
        type?: string,
        subtypes?: string[],
        protocol?: Protocols, // defaults to 'tcp'
        txt?: { // passed into dns-txt module
            binary?: boolean,
        },
    }

    export class BonjourHap {
        publish(options: PublishOptions): Service;
        unpublishAll(callback: () => void): void;
        destroy(): void;

        find(options?: BrowsingOptions, up?: ServiceCallback): Browser;
        findOne(options?: BrowsingOptions, callback?: ServiceCallback): Browser;
    }


    export type MulticastOptions = {
        multicast: boolean;
        interface: string;
        port: number;
        ip: string;
        ttl: number;
        loopback: boolean;
        reuseAddr: boolean;
    };
    function createWithOptions(options?: MulticastOptions): BonjourHap;

    export default createWithOptions;
}
