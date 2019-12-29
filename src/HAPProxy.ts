import {HAPClient} from "./HAPClient";
import {HAPServer} from "./HAPServer";

export class HAPProxy {

    private client: HAPClient;
    private server: HAPServer;


    constructor(client: HAPClient, server: HAPServer) {
        this.client = client;
        this.server = server;
    }

    // TODO /accessories: check for dataStream management characteristics; change the value of the accessory information name characteristic
    // TODO track event subscriptions

}
