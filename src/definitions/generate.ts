import fs, {WriteStream} from 'fs';
import path from 'path';

import plist from 'simple-plist';
import {uuid} from "../utils/uuid";

const metadataFile = "/System/Library/PrivateFrameworks/HomeKitDaemon.framework/Resources/plain-metadata.config";

type CharacteristicDefinition = {
    DefaultDescription: string,
    Format: string,
    LocalizationKey: string,
    Properties: number,
    ShortUUID: string,
    MaxValue?: number,
    MinValue?: number,
    StepValue?: number,
    Units?: string,
}

type ServiceDefinition = {
    Characteristics: {
        Optional: string[],
        Required: string[]
    },
    DefaultDescription: string,
    LocalizationKey: string,
    ShortUUID: string,
}

const plistData = plist.readFileSync(metadataFile);

let characteristics: Record<string, CharacteristicDefinition>;
let services: Record<string, ServiceDefinition>;
try {
    characteristics = checkDefined(plistData.PlistDictionary.HAP.Characteristics);
    services = checkDefined(plistData.PlistDictionary.HAP.Services);
} catch (error) {
    console.log("Unexpected structure of the plist file!");
    throw error;
}

const characteristicsOutput = fs.createWriteStream(path.join(__dirname, "CharacteristicType.ts"));
const serviceOutput = fs.createWriteStream(path.join(__dirname, "ServiceType.ts"));

writeBoth("// THIS FILE IS AUTO-GENERATED - DO NOT MODIFY\n");
writeBoth("\n");

/**
 * Characteristics
 */

characteristicsOutput.write("export enum CharacteristicType {\n");
characteristicsOutput.write("    // noinspection JSUnusedGlobalSymbols\n");

Object.entries(characteristics).forEach(([name, characteristic]) => {
   const id = uuid.toLongForm(characteristic.ShortUUID);
   const enumName = name.toUpperCase().replace(/-/g, "_").replace(/\./g, "_");

   characteristicsOutput.write(`    ${enumName} = "${id}",\n`);
});

characteristicsOutput.write("}\n");
writeTypeToName(characteristicsOutput, "CharacteristicType");
characteristicsOutput.end();
/**
 * Services
 */

serviceOutput.write("export enum ServiceType {\n");
serviceOutput.write("    // noinspection JSUnusedGlobalSymbols");

Object.entries(services).forEach(([name, service]) => {
    const id = uuid.toLongForm(service.ShortUUID);
    const enumName = name.toUpperCase().replace(/-/g, "_").replace(/\./g, "_");

    serviceOutput.write(`    ${enumName} = "${id}",\n`);
});

serviceOutput.write("}\n");
writeTypeToName(serviceOutput, "ServiceType");
serviceOutput.end();

function writeBoth(content: any) {
    characteristicsOutput.write(content);
    serviceOutput.write(content);
}

function checkDefined(input: any) {
    if (!input) {
        throw new Error("value is undefined!");
    }

    return input;
}

function writeTypeToName(output: WriteStream, name: string) {
    output.write(`
export namespace ${name}s {
    export const TYPE_TO_NAME: Record<string, string> = {};
}

for (let type in ${name}) {
    // @ts-ignore
    ${name}s.TYPE_TO_NAME[${name}[type]] = type;
}
`);
}
