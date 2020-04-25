import bonjour, {BonjourHap, Browser, MulticastOptions, Service} from 'bonjour-hap';
import {ClientInfo} from "../storage/ClientInfo";
import {EventEmitter} from "./EventEmitter";
import {HAPAccessoryCategory, PairingStatusFlags} from "../types/hap-proxy";
import Timeout = NodeJS.Timeout;

export interface HAPDeviceInfo {
    host: string,
    port: number,

    clientId: string,
    protocolVersion: string,

    configNumber: number,
    statusFlag: number,
    paired: boolean,

    category: HAPAccessoryCategory,
}

export enum BonjourBrowserEvents {
    UPDATE = "update",
    CONFIG_NUMBER_CHANGE = "config-change",
    PAIRED_CHANGE = "paired-change",
}

export type BonjourBrowserEventMap = {
    [BonjourBrowserEvents.UPDATE]: (deviceInfo: HAPDeviceInfo) => void;
    [BonjourBrowserEvents.CONFIG_NUMBER_CHANGE]: (configNumber: number) => void;
    [BonjourBrowserEvents.PAIRED_CHANGE]: (paired: boolean) => void;
}

export class HAPBonjourBrowser extends EventEmitter<BonjourBrowserEventMap> {

    private static readonly TIMEOUT = 3000; // give it 3s to discover the service on the network TODO (?)
    private static readonly INTERVAL = 30000; // 30s

    readonly clientInfo: ClientInfo;

    private bonjourService: BonjourHap;
    private browser?: Browser;

    private deviceInfo?: HAPDeviceInfo;

    private readonly promise: Promise<HAPDeviceInfo>;
    private timeout?: Timeout;
    private promiseResolver?: (value?: HAPDeviceInfo | PromiseLike<HAPDeviceInfo>) => void;

    private interval?: Timeout;

    constructor(clientInfo: ClientInfo, mdnsConfig?: MulticastOptions) {
        super();
        this.clientInfo = clientInfo;

        this.bonjourService = bonjour(mdnsConfig);
        this.browser = this.bonjourService.find({
            type: "hap",
        }, this.handleUp.bind(this));

        this.promise = new Promise<HAPDeviceInfo>((resolve, reject) => {
            this.promiseResolver = resolve;
            this.timeout = setTimeout(() => {
                reject("HAP device '" + this.clientInfo.accessoryName + "' could not be found on the network!");
            }, HAPBonjourBrowser.TIMEOUT);
        });
    }

    private handleUp(service: Service) {
        if (service.name !== this.clientInfo.accessoryName) {
            return; // ignore if this is not the service we are searching for
        }
        if (!this.browser) {
            return;
        }

        this.browser!.stop(); // bonjour-hap currently doesn't support events when txt records get updated
        this.browser = undefined;

        const txt: Record<string, any> = service.txt!
        const configNumber = txt["c#"];
        const statusFlag = txt["sf"];
        const protocolVersion = txt["pv"];
        const id = txt["id"];

        const category = txt["ci"];

        const paired = (statusFlag & PairingStatusFlags.PAIRED) !== 0;

        let configNumberChanged = false;
        let pairedStatusChanged = false;
        if (this.deviceInfo) {
            configNumberChanged = configNumber !== this.deviceInfo.configNumber;
            pairedStatusChanged = paired !== this.deviceInfo.paired;
        }

        this.deviceInfo = {
            host: service.host,
            port: service.port,

            clientId: id,
            protocolVersion: protocolVersion,

            configNumber: configNumber,
            statusFlag: statusFlag,
            paired: paired,

            category: category,
        };

        if (this.promiseResolver) {
            this.promiseResolver(this.deviceInfo);
            this.promiseResolver = undefined;

            if (this.timeout) {
                clearTimeout(this.timeout);
                this.timeout = undefined;
            }
        } else {
            this.emit(BonjourBrowserEvents.UPDATE, this.deviceInfo);
            if (configNumberChanged) {
                this.emit(BonjourBrowserEvents.CONFIG_NUMBER_CHANGE, this.deviceInfo.configNumber);
            }
            if (pairedStatusChanged) {
                this.emit(BonjourBrowserEvents.PAIRED_CHANGE, this.deviceInfo.paired);
            }
        }

        if (!this.interval) {
            this.interval = setInterval(() => {
                this.browser = this.bonjourService.find({
                    type: "hap",
                }, this.handleUp.bind(this));
            }, HAPBonjourBrowser.INTERVAL);
        }
    }

    async deviceInfoPromise() {
        if (this.deviceInfo) {
            return this.deviceInfo;
        } else {
            return await this.promise;
        }
    }

}
