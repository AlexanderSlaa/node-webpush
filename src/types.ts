'use strict';

import type { SupportedContentEncoding, SupportedUrgency } from './constants.js';

export type PushSubscription = {
    endpoint: string;
    keys?: {
        /** Base64url-encoded 65-byte uncompressed P-256 public key */
        p256dh: string;
        /** Base64url-encoded auth secret (>= 16 bytes recommended) */
        auth: string;
    };
};

export type WebPushConfig = {
    vapid: {
        publicKey: string;  // base64url, 65 bytes (uncompressed P-256)
        privateKey: string; // base64url, 32 bytes (P-256 scalar)
        subject: string | URL; // https: or mailto:
    };
    gcm?: {
        apiKey?: string | null;
    };
};

export type GenerateRequestOptions = {
    headers?: Record<string, string>;
    gcmAPIKey?: string | null;
    vapidDetails?: WebPushConfig['vapid'] | null;

    TTL?: number;
    contentEncoding?: SupportedContentEncoding;
    urgency?: SupportedUrgency;
    topic?: string;

    /**
     * RFC8188 compliance knob:
     * - Web Push RFC8291 requires a single record; this stays `false` by default.
     * - Set to `true` only if you intentionally want multi-record RFC8188 payload bodies.
     */
    allowMultipleRecords?: boolean;

    /**
     * RFC8188 record size (`rs`) in octets (ciphertext record size).
     * Must be >= 18.
     */
    rs?: number;

    /**
     * Optional number of 0x00 bytes inserted *after* the padding delimiter in the final record.
     * Usually 0 for Web Push.
     */
    finalRecordPadding?: number;
};

export type WebPushRequestDetails = {
    endpoint: string;
    init: RequestInit;
};
