const Sodium = require('sodium').api;
import tweetnacl from 'tweetnacl';

const longTerm = Sodium.crypto_sign_keypair();

const publicKey: Buffer = longTerm.publicKey;
const secretKey: Buffer = longTerm.secretKey;

console.log("publicKey: " + publicKey.length);
console.log("secretKey: " + secretKey.length);

const lt = tweetnacl.sign.keyPair();

console.log("publicKey: " + lt.publicKey.length);
console.log("privateKey: " + lt.secretKey.length);
