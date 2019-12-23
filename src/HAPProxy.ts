import {HAPClient} from "./HAPClient";
import {HAPServer} from "./HAPServer";

export class HAPProxy {

    private client: HAPClient;
    private server: HAPServer;


    constructor(client: HAPClient, server: HAPServer) { // use the same stuff as HAPClient info maybe?
        this.client = client;
        this.server = server;
    }

}
