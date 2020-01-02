import crypto from 'crypto';
import bonjour, { BonjourHap, MulticastOptions, Service } from 'bonjour-hap';
import {AccessoryInfo} from "../storage/AccessoryInfo";
import createDebug from 'debug';

const debug = createDebug("HAPServer:Advertiser");

export class Advertiser {

    static protocolVersion: string = "1.1";
    //static protocolVersionService: string = "1.1.0";

    readonly accessoryInfo: AccessoryInfo;

    private bonjourService: BonjourHap;
    private advertisement?: Service;
    private readonly setupHash: string;

    constructor(accessoryInfo: AccessoryInfo, mdnsConfig?: MulticastOptions) {
        this.accessoryInfo = accessoryInfo;

        this.bonjourService = bonjour(mdnsConfig);
        this.setupHash = this.genSetupHash();
    }

    startAdvertising(port: number) {
        if (this.advertisement) {
            this.stopAdvertising();
        }

        /**
         * The host name of the component is probably better to be
         * the username of the hosted accessory + '.local'.
         * By default 'bonjour' doesnt add '.local' at the end of the os.hostname
         * this causes to return 'raspberrypi' on raspberry pi / raspbian
         * then when the phone queryies for A/AAAA record it is being queried
         * on normal dns, not on mdns. By Adding the username of the accessory
         * probably the problem will also fix a possible problem
         * of having multiple pi's on same network
         */
        const host = this.accessoryInfo.accessoryId.replace(/:/ig, "_") + '.local';

        this.advertisement = this.bonjourService.publish({
            name: this.accessoryInfo.displayName,
            type: "hap",
            port: port,
            txt: this.txtRecord(),
            host: host
        });

        debug("Started advertisement for '%s'", this.accessoryInfo.displayName);
    }

    updateAdvertisement(){
        if (this.advertisement) {
            this.advertisement.updateTxt(this.txtRecord());

            debug("Updated advertisement for '%s'", this.accessoryInfo.displayName);
        }
    }

    stopAdvertising() {
        debug("Stopping advertisement for '%s'", this.accessoryInfo.displayName);

        if (this.advertisement) {
            this.advertisement.stop();
            this.advertisement.destroy();
            this.advertisement = undefined;
        }

        this.bonjourService.destroy();
    }

    private txtRecord() {
        return {
            md: this.accessoryInfo.displayName,
            pv: Advertiser.protocolVersion,
            id: this.accessoryInfo.accessoryId,
            // "accessory conf" - represents the "configuration version" of an Accessory. Increasing this "version number" signals iOS devices to re-fetch /accessories data.
            "c#": `${this.accessoryInfo.configNumber}`,
            "s#": "1", // "accessory state", should always be 1 however certified devices increment it :thinking:
            "ff": "0",
            "ci": `${this.accessoryInfo.category}`,
            "sf": this.accessoryInfo.hasPairings() ? "0" : "1",
            "sh": this.setupHash
        };
    }

    private genSetupHash() {
        const material = this.accessoryInfo.setupID + this.accessoryInfo.accessoryId;
        const hash = crypto.createHash("sha512");
        hash.update(material);

        return hash.digest().slice(0, 4).toString("base64");
    }
}

