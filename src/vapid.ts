'use strict';

import crypto from 'crypto';
import {base64url} from './utils/base64url';
import {SupportedContentEncoding} from './constants';

const DEFAULT_EXPIRATION_SECONDS = 12 * 60 * 60;
const MAX_EXPIRATION_SECONDS = 24 * 60 * 60;

function getFutureExpirationTimestamp(numSeconds: number): number {
    const future = new Date();
    future.setSeconds(future.getSeconds() + numSeconds);
    return Math.floor(future.getTime() / 1000);
}

export const Validate = {
    subject(subject: string | URL): void {
        if (!subject) throw new Error('No subject set in VAPID details.');
        const u = typeof subject === 'string' ? new URL(subject) : subject;
        if (!['https:', 'mailto:'].includes(u.protocol)) {
            throw new Error(`VAPID subject must be https: or mailto:. Got: ${u.toString()}`);
        }
        if (u.hostname === 'localhost') {
            console.warn('VAPID subject points to localhost; some push services may reject this.');
        }
    },

    publicKey(publicKey: string): void {
        if (!publicKey) throw new Error('No VAPID public key set.');
        if (typeof publicKey !== 'string' || !base64url.validate(publicKey)) {
            throw new Error('VAPID public key must be base64url without "=" padding.');
        }
        const pk = base64url.toBuffer(publicKey);
        if (pk.length !== 65 || pk[0] !== 0x04) {
            throw new Error('VAPID public key must decode to 65-byte uncompressed P-256.');
        }
    },

    privateKey(privateKey: string): void {
        if (!privateKey) throw new Error('No VAPID private key set.');
        if (typeof privateKey !== 'string' || !base64url.validate(privateKey)) {
            throw new Error('VAPID private key must be base64url without "=" padding.');
        }
        const sk = base64url.toBuffer(privateKey);
        if (sk.length !== 32) throw new Error('VAPID private key must decode to 32 bytes.');
    },

    expiration(expiration: number): void {
        if (!Number.isInteger(expiration)) throw new Error('VAPID expiration must be an integer.');
        if (expiration < 0) throw new Error('VAPID expiration must be positive.');
        const maxExp = getFutureExpirationTimestamp(MAX_EXPIRATION_SECONDS);
        if (expiration >= maxExp) throw new Error('VAPID expiration exceeds 24 hours.');
    },

    audience(audience: string | URL): void {
        if (!audience) throw new Error('No audience set for VAPID.');
        const a = typeof audience === 'string' ? new URL(audience) : audience;
        if (!a.origin || a.origin === 'null') {
            throw new Error(`VAPID audience must be an origin. Got: ${a.toString()}`);
        }
    },
};

export function GenerateKeys(): { publicKey: string; privateKey: string } {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();

    let pub = ecdh.getPublicKey();
    let priv = ecdh.getPrivateKey();

    if (priv.length < 32) priv = Buffer.concat([Buffer.alloc(32 - priv.length, 0x00), priv]);
    if (pub.length < 65) pub = Buffer.concat([Buffer.alloc(65 - pub.length, 0x00), pub]);

    return {publicKey: base64url.toString(pub), privateKey: base64url.toString(priv)};
}

function publicKeyToJwk(publicKeyB64Url: string): { x: string; y: string } {
    const pub = base64url.toBuffer(publicKeyB64Url);
    if (pub.length !== 65 || pub[0] !== 0x04) throw new Error('Invalid uncompressed P-256 public key.');
    return {x: base64url.toString(pub.subarray(1, 33)), y: base64url.toString(pub.subarray(33, 65))};
}

function privateKeyToJwk(privateKeyB64Url: string): string {
    const d = base64url.toBuffer(privateKeyB64Url);
    if (d.length !== 32) throw new Error('Invalid P-256 private key scalar.');
    return base64url.toString(d);
}

function derToJose(derSig: Buffer, keySizeBytes = 32): Buffer {
    let off = 0;
    if (derSig[off++] !== 0x30) throw new Error('Invalid DER signature (expected SEQUENCE).');

    let seqLen = derSig[off++];
    if (seqLen & 0x80) {
        const n = seqLen & 0x7f;
        off += n;
    }

    if (derSig[off++] !== 0x02) throw new Error('Invalid DER signature (expected INTEGER r).');
    const rLen = derSig[off++];
    let r = derSig.subarray(off, off + rLen);
    off += rLen;

    if (derSig[off++] !== 0x02) throw new Error('Invalid DER signature (expected INTEGER s).');
    const sLen = derSig[off++];
    let s = derSig.subarray(off, off + sLen);

    if (r[0] === 0x00) r = r.subarray(1);
    if (s[0] === 0x00) s = s.subarray(1);

    if (r.length > keySizeBytes || s.length > keySizeBytes) throw new Error('Invalid DER signature size.');
    const rPad = Buffer.concat([Buffer.alloc(keySizeBytes - r.length, 0x00), r]);
    const sPad = Buffer.concat([Buffer.alloc(keySizeBytes - s.length, 0x00), s]);
    return Buffer.concat([rPad, sPad]);
}

function signJwtES256(payload: Record<string, unknown>, privateKeyB64Url: string, publicKeyB64Url: string): string {
    const header = {typ: 'JWT', alg: 'ES256'};
    const encodedHeader = base64url.toJSON(header);
    const encodedPayload = base64url.toJSON(payload);
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const {x, y} = publicKeyToJwk(publicKeyB64Url);
    const d = privateKeyToJwk(privateKeyB64Url);

    const keyObject = crypto.createPrivateKey({
        key: {kty: 'EC', crv: 'P-256', x, y, d},
        format: 'jwk',
    });

    const derSig = crypto.sign('sha256', Buffer.from(signingInput, 'utf8'), {
        key: keyObject,
        dsaEncoding: 'der',
    });

    const joseSig = derToJose(derSig, 32);
    const encodedSig = base64url.toString(joseSig);
    return `${signingInput}.${encodedSig}`;
}

export function GenerateHeaders(input: {
    audience: string | URL;
    subject: string | URL;
    publicKey: string;
    privateKey: string;
    contentEncoding: SupportedContentEncoding;
    expiration?: number;
}): Headers {
    Validate.audience(input.audience);
    Validate.subject(input.subject);
    Validate.publicKey(input.publicKey);
    Validate.privateKey(input.privateKey);

    const audience = (typeof input.audience === 'string' ? new URL(input.audience) : input.audience).origin;
    const subject = (typeof input.subject === 'string' ? new URL(input.subject) : input.subject).toString();

    const exp = input.expiration ?? getFutureExpirationTimestamp(DEFAULT_EXPIRATION_SECONDS);
    Validate.expiration(exp);

    const jwt = signJwtES256({aud: audience, exp, sub: subject}, input.privateKey, input.publicKey);

    const headers = new Headers();
    if (input.contentEncoding === SupportedContentEncoding.AES_128_GCM) {
        headers.set('Authorization', `vapid t=${jwt}, k=${input.publicKey}`);
    } else if (input.contentEncoding === SupportedContentEncoding.AES_GCM) {
        headers.set('Authorization', `WebPush ${jwt}`);
        headers.set('Crypto-Key', `p256ecdsa=${input.publicKey}`);
    } else {
        throw new Error(`Unsupported content encoding: ${input.contentEncoding}`);
    }
    return headers;
}

