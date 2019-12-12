import assert from 'assert';

import createDebug from 'debug';
import tweetnacl from 'tweetnacl';

import * as chacha20poly1305 from './chacha20poly1305';
import {HAPEncryptionContext} from "../../HAPClient";

const debug = createDebug('encryption');

function fromHex(h: string) {
  h.replace(/([^0-9a-f])/g, '');
  let out = [], len = h.length, w = '';
  for (let i = 0; i < len; i += 2) {
    w = h[i];
    if (((i+1) >= len) || typeof h[i+1] === 'undefined') {
        w += '0';
    } else {
        w += h[i+1];
    }
    out.push(parseInt(w, 16));
  }
  return out;
}

export function generateCurve25519KeyPair() {
  return tweetnacl.box.keyPair();
}

export function generateCurve25519SharedSecKey(priKey: Uint8Array, pubKey: Uint8Array) {
  return tweetnacl.scalarMult(priKey, pubKey);
}

//Security Layer Enc/Dec

type Count = {
  value: any;
}

export function layerEncrypt(data: Buffer, context: HAPEncryptionContext) {
  let result = Buffer.alloc(0);
  const total = data.length;
  for (let offset = 0; offset < total; ) {
    const length = Math.min(total - offset, 0x400);
    const leLength = Buffer.alloc(2);
    leLength.writeUInt16LE(length,0);

    const nonce = Buffer.alloc(8);
    writeUInt64LE(context.controllerToAccessoryNonce++, nonce, 0);

    const result_Buffer = Buffer.alloc(length);
    const result_mac = Buffer.alloc(16);
    encryptAndSeal(context.controllerToAccessoryKey, nonce, data.slice(offset, offset + length),
      leLength,result_Buffer, result_mac);

    offset += length;

    result = Buffer.concat([result,leLength,result_Buffer,result_mac]);
  }
  return result;
}

export function layerDecrypt(packet: Buffer, context: HAPEncryptionContext) {
  // Handle Extra Info
  if (context.frameBuffer != undefined) {
    packet = Buffer.concat([context.frameBuffer, packet]);
  }

  let result = Buffer.alloc(0);
  const total = packet.length;

  for (let offset = 0; offset < total;) {
    const realDataLength = packet.slice(offset, offset + 2).readUInt16LE(0);

    const availableDataLength = total - offset - 2 - 16;
    if (realDataLength > availableDataLength) {
      // Fragmented packet
      context.frameBuffer = packet.slice(offset);
      break;
    } else {
      context.frameBuffer = undefined;
    }

    const nonce = Buffer.alloc(8);
    writeUInt64LE(context.accessoryToControllerNonce++, nonce, 0);

    const result_Buffer = Buffer.alloc(realDataLength);

    if (verifyAndDecrypt(context.accessoryToControllerKey, nonce, packet.slice(offset + 2, offset + 2 + realDataLength),
      packet.slice(offset + 2 + realDataLength, offset + 2 + realDataLength + 16),
      packet.slice(offset,offset+2),result_Buffer)) {
        result = Buffer.concat([result,result_Buffer]);
        offset += (18 + realDataLength);
      } else {
        console.error('Layer Decrypt fail!');
        console.error('Packet: %s', packet.toString('hex'));
        throw new Error("Unable to authenticate cipherText!");
      }
  }

  return result;
}

//General Enc/Dec
export function verifyAndDecrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer, mac: Buffer, addData: Buffer | null | undefined, plaintext: Buffer) {
  const ctx = new chacha20poly1305.Chacha20Ctx();
  chacha20poly1305.chacha20_keysetup(ctx, key);
  chacha20poly1305.chacha20_ivsetup(ctx, nonce);
  const poly1305key = Buffer.alloc(64);
  const zeros = Buffer.alloc(64);
  chacha20poly1305.chacha20_update(ctx,poly1305key,zeros,zeros.length);

  const poly1305_contxt = new chacha20poly1305.Poly1305Ctx();
  chacha20poly1305.poly1305_init(poly1305_contxt, poly1305key);

  let addDataLength = 0;
  if (addData != undefined) {
    addDataLength = addData.length;
    chacha20poly1305.poly1305_update(poly1305_contxt, addData, addData.length);
    if ((addData.length % 16) != 0) {
      chacha20poly1305.poly1305_update(poly1305_contxt, Buffer.alloc(16-(addData.length%16)), 16-(addData.length%16));
    }
  }

  chacha20poly1305.poly1305_update(poly1305_contxt, ciphertext, ciphertext.length);
  if ((ciphertext.length % 16) != 0) {
    chacha20poly1305.poly1305_update(poly1305_contxt, Buffer.alloc(16-(ciphertext.length%16)), 16-(ciphertext.length%16));
  }

  const leAddDataLen = Buffer.alloc(8);
  writeUInt64LE(addDataLength, leAddDataLen, 0);
  chacha20poly1305.poly1305_update(poly1305_contxt, leAddDataLen, 8);

  const leTextDataLen = Buffer.alloc(8);
  writeUInt64LE(ciphertext.length, leTextDataLen, 0);
  chacha20poly1305.poly1305_update(poly1305_contxt, leTextDataLen, 8);

  const poly_out = [] as unknown as Uint8Array;
  chacha20poly1305.poly1305_finish(poly1305_contxt, poly_out);

  if (chacha20poly1305.poly1305_verify(mac, poly_out) != 1) {
    debug('Verify Fail');
    return false;
  } else {
    const written = chacha20poly1305.chacha20_update(ctx, plaintext, ciphertext, ciphertext.length);
    chacha20poly1305.chacha20_final(ctx,plaintext.slice(written, ciphertext.length));
    return true;
  }
}

export function encryptAndSeal(key: Buffer, nonce: Buffer, plaintext: Buffer, addData: Buffer | null | undefined, ciphertext: Buffer, mac: Buffer) {
  const ctx = new chacha20poly1305.Chacha20Ctx();
  chacha20poly1305.chacha20_keysetup(ctx, key);
  chacha20poly1305.chacha20_ivsetup(ctx, nonce);
  const poly1305key = Buffer.alloc(64);
  const zeros = Buffer.alloc(64);
  chacha20poly1305.chacha20_update(ctx,poly1305key,zeros,zeros.length);

  const written = chacha20poly1305.chacha20_update(ctx, ciphertext, plaintext, plaintext.length);
  chacha20poly1305.chacha20_final(ctx,ciphertext.slice(written,plaintext.length));

  const poly1305_contxt = new chacha20poly1305.Poly1305Ctx();
  chacha20poly1305.poly1305_init(poly1305_contxt, poly1305key);

  let addDataLength = 0;
  if (addData != undefined) {
    addDataLength = addData.length;
    chacha20poly1305.poly1305_update(poly1305_contxt, addData, addData.length);
    if ((addData.length % 16) != 0) {
      chacha20poly1305.poly1305_update(poly1305_contxt, Buffer.alloc(16-(addData.length%16)), 16-(addData.length%16));
    }
  }

  chacha20poly1305.poly1305_update(poly1305_contxt, ciphertext, ciphertext.length);
  if ((ciphertext.length % 16) != 0) {
    chacha20poly1305.poly1305_update(poly1305_contxt, Buffer.alloc(16-(ciphertext.length%16)), 16-(ciphertext.length%16));
  }

  const leAddDataLen = Buffer.alloc(8);
  writeUInt64LE(addDataLength, leAddDataLen, 0);
  chacha20poly1305.poly1305_update(poly1305_contxt, leAddDataLen, 8);

  const leTextDataLen = Buffer.alloc(8);
  writeUInt64LE(ciphertext.length, leTextDataLen, 0);
  chacha20poly1305.poly1305_update(poly1305_contxt, leTextDataLen, 8);

  chacha20poly1305.poly1305_finish(poly1305_contxt, mac);
}

const MAX_UINT32 = 0x00000000FFFFFFFF;
const MAX_INT53 = 0x001FFFFFFFFFFFFF;

function onesComplement(number: number) {
  number = ~number;
  if (number < 0) {
    number = (number & 0x7FFFFFFF) + 0x80000000
  }
  return number
}

function uintHighLow(number: number) {
  assert(number > -1 && number <= MAX_INT53, "number out of range");
  assert(Math.floor(number) === number, "number must be an integer");
  let high = 0;
  const signbit = number & 0xFFFFFFFF;
  const low = signbit < 0 ? (number & 0x7FFFFFFF) + 0x80000000 : signbit;
  if (number > MAX_UINT32) {
    high = (number - low) / (MAX_UINT32 + 1)
  }
  return [high, low]
}

function intHighLow(number: number) {
  if (number > -1) {
    return uintHighLow(number)
  }
  const hl = uintHighLow(-number);
  let high = onesComplement(hl[0]);
  let low = onesComplement(hl[1]);
  if (low === MAX_UINT32) {
    high += 1;
    low = 0
  }
  else {
    low += 1
  }
  return [high, low]
}

function writeUInt64BE(number: number, buffer: Buffer, offset: number = 0) {
  const hl = uintHighLow(number);
  buffer.writeUInt32BE(hl[0], offset);
  buffer.writeUInt32BE(hl[1], offset + 4)
}

export function writeUInt64LE (number: number, buffer: Buffer, offset: number = 0) {
  const hl = uintHighLow(number);
  buffer.writeUInt32LE(hl[1], offset);
  buffer.writeUInt32LE(hl[0], offset + 4)
}