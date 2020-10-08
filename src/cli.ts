// we are running ciao beta right now, disable the debug log
if (!process.env.DEBUG) {
  process.env.DEBUG = "ciao:disabled";
} else if (!process.env.DEBUG.includes("ciao")) {
  process.env.DEBUG += ",ciao:disabled";
}

import {version} from "punycode";
import {AccessoryInfo} from "./storage/AccessoryInfo";
import {HAPProxy} from "./HAPProxy";
import {ClientInfo} from "./storage/ClientInfo";
import { Command } from "commander";

function getVersion(): string {
  const packageJson = require("../package.json");
  return packageJson.version;
}

// DEBUG=HAPClient:*,HAPServer,HAPServer:*,HAPProxy,DataStream:* ts-node --files src/cli.ts
// DEBUG=Accessory,HAPServer,StreamController,DataStream:*,EventedHTTPServer ts-node --files src/Core.ts

// TODO code linting etc (code style)

const command = new Command()
  .version(version)
  .option("-p, --port <port>", "define the proxy port", parseInt, 60141)
  .requiredOption("-t, --target-name <instance name>", "define the instance name of the device which should be proxied")
  .requiredOption("-c, --target-pincode <pincode>", "define the pincode with dashes of the homekit device to be proxied")
  .option("--proxy-pincode <pincode>", "define a separate pincode for the proxy server");

command.parse(process.argv);
const opts = command.opts();

const port: number = opts.port || 0;

const targetName: string = opts.targetName;
const targetPincode: string = opts.targetPincode;

const proxyName = "Proxy " + targetName;
const proxyPincode: string = opts.proxyPincode || targetPincode;

console.log(`Creating '${proxyName} to proxy ${targetName} on port ${port}...'`);

const accessoryInfo = new AccessoryInfo(proxyName, proxyPincode);
const clientInfo = new ClientInfo(targetName, targetPincode);

const proxy = new HAPProxy(clientInfo, accessoryInfo);
proxy.listen(port);


