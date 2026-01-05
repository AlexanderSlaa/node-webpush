'use strict';

import crypto from 'crypto';
import { base64url } from '../utils/base64url';
import { u16be, u32be } from '../utils/binary';
import { buildPlaintextRecords, encryptRecords } from './rfc8188';

function hmacSha256(key: Buffer, data: Buffer): Buffer {
    return crypto.createHmac('sha256', key).update(data).digest();
}

function assertSubscriptionKeys(p256dh: string, auth: string): void {
    if (!p256dh || typeof p256dh !== 'string') throw new Error('subscription.keys.p256dh must be a string');
    if (!auth || typeof auth !== 'string') throw new Error('subscription.keys.auth must be a string');

    const p256dhBytes = base64url.toBuffer(p256dh);
    if (p256dhBytes.length !== 65 || p256dhBytes[0] !== 0x04) {
        throw new Error('subscription.keys.p256dh must decode to a 65-byte uncompressed P-256 public key');
    }

    const authBytes = base64url.toBuffer(auth);
    if (authBytes.length < 16) throw new Error('subscription.keys.auth must decode to at least 16 bytes');
}

/**
 * Encrypt a push payload using RFC8291 + RFC8188 with aes128gcm.
 *
 * Returns the full RFC8188 body:
 *   salt(16) || rs(4) || idlen(1) || keyid(=sender pubkey) || encryptedRecords
 */
export function encryptAes128GcmBody(params: {
    p256dh: string;
    auth: string;
    payload: Buffer;
    rs: number;
    allowMultipleRecords: boolean;
    finalRecordPadding: number;
}): Buffer {
    assertSubscriptionKeys(params.p256dh, params.auth);

    const uaPublic = base64url.toBuffer(params.p256dh);
    const authSecret = base64url.toBuffer(params.auth);

    // Sender ephemeral key
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    const asPublic = ecdh.getPublicKey(); // 65 bytes
    const ecdhSecret = ecdh.computeSecret(uaPublic);

    // RFC8291: random salt
    const salt = crypto.randomBytes(16);

    // RFC8291: PRK_key = HMAC(auth_secret, ecdh_secret)
    const prkKey = hmacSha256(authSecret, ecdhSecret);

    // key_info = "WebPush: info" || 0x00 || ua_public || as_public
    const keyInfo = Buffer.concat([Buffer.from('WebPush: info', 'utf8'), Buffer.from([0x00]), uaPublic, asPublic]);

    // IKM = HMAC(PRK_key, key_info || 0x01)
    const ikm = hmacSha256(prkKey, Buffer.concat([keyInfo, Buffer.from([0x01])]));

    // RFC8188: PRK = HMAC(salt, IKM)
    const prk = hmacSha256(salt, ikm);

    // RFC8188: CEK / nonce derivation
    const cekInfo = Buffer.concat([Buffer.from('Content-Encoding: aes128gcm', 'utf8'), Buffer.from([0x00])]);
    const nonceInfo = Buffer.concat([Buffer.from('Content-Encoding: nonce', 'utf8'), Buffer.from([0x00])]);

    const cek = hmacSha256(prk, Buffer.concat([cekInfo, Buffer.from([0x01])])).subarray(0, 16);
    const baseNonce = hmacSha256(prk, Buffer.concat([nonceInfo, Buffer.from([0x01])])).subarray(0, 12);

    const plaintextRecords = buildPlaintextRecords({
        message: params.payload,
        rs: params.rs,
        allowMultipleRecords: params.allowMultipleRecords,
        finalRecordPadding: params.finalRecordPadding,
    });

    const encryptedRecords = encryptRecords({ cek, baseNonce, plaintextRecords });

    // RFC8188 header: salt || rs || idlen || keyid
    if (asPublic.length !== 65) throw new Error('Sender public key must be 65 bytes');

    return Buffer.concat([salt, u32be(params.rs), Buffer.from([asPublic.length]), asPublic, encryptedRecords]);
}

/**
 * Legacy aesgcm encryption for interop.
 * Returns ciphertext plus values needed for headers: Encryption (salt) and Crypto-Key (dh).
 */
export function encryptAesGcmLegacy(params: {
    p256dh: string;
    auth: string;
    payload: Buffer;
}): { saltB64Url: string; localPublicKey: Buffer; ciphertext: Buffer } {
    assertSubscriptionKeys(params.p256dh, params.auth);

    const receiverPub = base64url.toBuffer(params.p256dh);
    const authSecret = base64url.toBuffer(params.auth);

    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    const senderPub = ecdh.getPublicKey();
    const ecdhSecret = ecdh.computeSecret(receiverPub);

    const salt = crypto.randomBytes(16);

    const prkKey = hmacSha256(authSecret, ecdhSecret);
    const keyInfo = Buffer.concat([Buffer.from('WebPush: info', 'utf8'), Buffer.from([0x00]), receiverPub, senderPub]);
    const ikm = hmacSha256(prkKey, Buffer.concat([keyInfo, Buffer.from([0x01])]));
    const prk = hmacSha256(salt, ikm);

    const cekInfo = Buffer.concat([Buffer.from('Content-Encoding: aesgcm', 'utf8'), Buffer.from([0x00])]);
    const nonceInfo = Buffer.concat([Buffer.from('Content-Encoding: nonce', 'utf8'), Buffer.from([0x00])]);

    const cek = hmacSha256(prk, Buffer.concat([cekInfo, Buffer.from([0x01])])).subarray(0, 16);
    const nonce = hmacSha256(prk, Buffer.concat([nonceInfo, Buffer.from([0x01])])).subarray(0, 12);

    const padLen = 0;
    const plaintext = Buffer.concat([u16be(padLen), Buffer.alloc(padLen, 0x00), params.payload]);

    const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return { saltB64Url: base64url.toString(salt), localPublicKey: senderPub, ciphertext: Buffer.concat([enc, tag]) };
}
