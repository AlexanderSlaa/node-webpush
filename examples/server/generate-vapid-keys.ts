'use strict';

// Run: npx tsx examples/server/generate-vapid-keys.ts
//
// Prints a fresh VAPID key pair. Run this once, then store the values as
// VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY env vars (see ../README.md).

import {VAPID} from '../../src/index.js';

const {publicKey, privateKey} = VAPID.GenerateKeys();

console.log('VAPID_PUBLIC_KEY=' + publicKey);
console.log('VAPID_PRIVATE_KEY=' + privateKey);
