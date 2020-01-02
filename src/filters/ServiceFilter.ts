import {HAPProxy} from "../HAPProxy";
import {CharacteristicFilter, CharacteristicFilterConstructor} from "./CharacteristicFilter";

export abstract class ServiceFilter {

    readonly context: HAPProxy;
    readonly aid: number; // accessory id the service is associated with
    readonly iid: number; // instance id of the service an instance of this filter is used for

    // record holding the actual filter instances; indexed by iid (iid of the characteristic)
    readonly characteristicsFilters: Record<number, CharacteristicFilter<any>> = {};

    /**
     * Record of filter definitions. Key is the CharacteristicType and value the constructor of the CharacteristicFilter.
     */
    abstract characteristicFilterDefinitions: Record<string, CharacteristicFilterConstructor<any>>;

    /**
     * Creates a new instance of a ServiceFilter
     *
     * @param context {HAPProxy} - the associated proxy instance
     * @param aid {number} - accessory id
     * @param iid {number} - instance id of the service
     */
    public constructor(context: HAPProxy, aid: number, iid: number) {
        this.context = context;
        this.aid = aid;
        this.iid = iid;
    }

}

/**
 * Creates a new instance of a ServiceFilter
 *
 * @param context {HAPProxy} - the associated proxy instance
 * @param aid {number} - accessory id
 * @param iid {number} - instance id of the service
 */
export type ServiceFilterConstructor = new(context: HAPProxy, aid: number, iid: number) => ServiceFilter;
