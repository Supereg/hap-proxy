import ciao, {
    CiaoService,
    MDNSServerOptions,
    Responder,
    ServiceEvent,
    ServiceTxt,
    ServiceType
} from "@homebridge/ciao";
import { ServiceOptions } from "@homebridge/ciao/lib/CiaoService";
import crypto from 'crypto';
import { EventEmitter } from "events";
import {AccessoryInfo} from "../storage/AccessoryInfo";

/**
 * This enum lists all bitmasks for all known status flags.
 * When the bit for the given bitmask is set, it represents the state described by the name.
 */
export const enum StatusFlag {
    // noinspection JSUnusedGlobalSymbols
    NOT_PAIRED = 0x01,
    NOT_JOINED_WIFI = 0x02,
    PROBLEM_DETECTED = 0x04,
}

/**
 * This enum lists all bitmasks for all known pairing feature flags.
 * When the bit for the given bitmask is set, it represents the state described by the name.
 */
export const enum PairingFeatureFlag {
    // noinspection JSUnusedGlobalSymbols
    SUPPORTS_HARDWARE_AUTHENTICATION = 0x01,
    SUPPORTS_SOFTWARE_AUTHENTICATION = 0x02,
}

export const enum AdvertiserEvent {
    UPDATED_NAME = "updated-name",
}

export declare interface Advertiser {
    on(event: "updated-name", listener: (name: string) => void): this;

    emit(event: "updated-name", name: string): boolean;
}

/**
 * Advertiser uses mdns to broadcast the presence of an Accessory to the local network.
 *
 * Note that as of iOS 9, an accessory can only pair with a single client. Instead of pairing your
 * accessories with multiple iOS devices in your home, Apple intends for you to use Home Sharing.
 * To support this requirement, we provide the ability to be "discoverable" or not (via a "service flag" on the
 * mdns payload).
 */
export class Advertiser extends EventEmitter {

    static protocolVersion: string = "1.1";
    // static protocolVersionService: string = "1.1.0";

    private readonly accessoryInfo: AccessoryInfo;
    private readonly setupHash: string;

    private readonly responder: Responder;
    private advertisedService?: CiaoService;

    constructor(accessoryInfo: AccessoryInfo, responderOptions?: MDNSServerOptions) {
        super();
        this.accessoryInfo = accessoryInfo;
        this.setupHash = this.computeSetupHash();

        this.responder = ciao.getResponder(responderOptions);
    }

    public createService(port: number, serviceOptions?: Partial<ServiceOptions>): void {
        this.advertisedService = this.responder.createService({
            name: this.accessoryInfo.displayName,
            type: ServiceType.HAP,
            txt: this.createTxt(),
            port: port,
            // host will default now to <displayName>.local, spaces replaced with dashes
            ...serviceOptions,
        });
        this.advertisedService.on(ServiceEvent.NAME_CHANGED, this.emit.bind(this, AdvertiserEvent.UPDATED_NAME));
    }

    public startAdvertising(): Promise<void> {
        return this.advertisedService!.advertise();
    }

    public updateAdvertisement(): void {
        this.advertisedService!.updateTxt(this.createTxt());
    }

    public destroyAdvertising(): Promise<void> {
        return this.advertisedService!.destroy();
    }

    public async shutdown(): Promise<void> { // TODO shutdown
        await this.destroyAdvertising(); // would also be done by the shutdown method below
        await this.responder.shutdown();
        this.removeAllListeners();
    }

    private createTxt(): ServiceTxt {
        const statusFlags: StatusFlag[] = [];

        if (!this.accessoryInfo.hasPairings()) {
            statusFlags.push(StatusFlag.NOT_PAIRED);
        }

        return {
            "c#": this.accessoryInfo.configNumber, // current configuration number
            ff: Advertiser.ff(), // pairing feature flags
            id: this.accessoryInfo.accessoryId, // device id
            md: this.accessoryInfo.displayName, // model name TODO we don't know the model yet
            pv: Advertiser.protocolVersion, // protocol version
            "s#": 1, // current state number (must be 1)
            sf: Advertiser.sf(...statusFlags), // status flags
            ci: this.accessoryInfo.category,
            sh: this.setupHash,
        };
    }

    private computeSetupHash(): string {
        const hash = crypto.createHash('sha512');
        hash.update(this.accessoryInfo.setupID + this.accessoryInfo.accessoryId.toUpperCase());
        return hash.digest().slice(0, 4).toString('base64');
    }

    public static ff(...flags: PairingFeatureFlag[]): number {
        let value = 0;
        flags.forEach(flag => value |= flag);
        return value;
    }

    public static sf(...flags: StatusFlag[]): number {
        let value = 0;
        flags.forEach(flag => value |= flag);
        return value;
    }

}

