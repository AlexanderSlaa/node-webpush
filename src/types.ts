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

/**
 * Response shape `notify()` actually depends on - deliberately not the global `Response` type.
 * A spec-compliant fetch implementation from outside lib.dom (undici's own `fetch` export is the
 * motivating case: its `Response` and lib.dom's `Response` are structurally near-identical at
 * runtime but not nominally assignable to each other in TS, e.g. `headers.entries()`'s iterator
 * type) still satisfies this without a consumer-side cast.
 */
export type FetchLikeResponse = {
    ok: boolean;
    status: number;
    statusText: string;
    text(): Promise<string>;
    headers: { get(name: string): string | null };
};

/**
 * Request init shape `generateRequest()` actually builds - deliberately not the global
 * `RequestInit` type, for the same lib.dom-vs-undici reason as {@link FetchLikeResponse} (this
 * time on `body`'s `FormData` member: DOM's and undici's `FormData` classes aren't mutually
 * assignable). `body` only ever needs to hold the encrypted payload Buffer - nothing here ever
 * constructs a FormData, Blob, or ReadableStream body.
 */
export type FetchLikeInit = {
    method?: string;
    headers?: Record<string, string>;
    body?: Buffer | Uint8Array | string | null;
};

/**
 * A fetch-like function. Deliberately looser than `typeof fetch` for the same reason as
 * {@link FetchLikeResponse} - so alternatives like undici's `fetch` (or any other spec-compliant
 * implementation) are assignable as-is. `input` is narrowed to `string | URL` (dropping
 * `Request`) because that's genuinely all `notify()` ever passes - `generateRequest()`'s
 * `endpoint` is always a plain string - and lib.dom's `Request` vs. undici's own aren't
 * mutually assignable (undici's requires `duplex`), which would otherwise force a
 * consumer-side cast for no real gain: nothing here ever constructs a `Request` object.
 *
 * A plain `FetchLikeInit` (not the global `RequestInit`) for the same reason, and to keep
 * `generateRequest()`'s own return type consistent with what gets passed to it - see
 * {@link FetchLikeInit}. `generateRequest()`'s returned `init` is usable as a real `RequestInit`
 * unchanged (its fields are a subset). The other direction - a value typed `typeof fetch` isn't
 * structurally assignable to `FetchLike`, purely a TS/Node generic-`Uint8Array` version quirk on
 * `body`, not a real runtime mismatch - is why `WebPush` adapts the global fetch through one
 * small wrapper internally (see `defaultFetch` in webpush.ts) rather than relying on that
 * assignability here.
 */
export type FetchLike = (input: string | URL, init?: FetchLikeInit) => Promise<FetchLikeResponse>;

export type WebPushConfig = {
    vapid: {
        publicKey: string;  // base64url, 65 bytes (uncompressed P-256)
        privateKey: string; // base64url, 32 bytes (P-256 scalar)
        subject: string | URL; // https: or mailto:
    };
    gcm?: {
        apiKey?: string | null;
    };

    /**
     * Override for the `fetch` implementation `notify()` uses to send the request.
     * Defaults to the global `fetch`. Useful in runtimes without one, or to plug in
     * a wrapped/instrumented fetch (retries, logging, proxying, etc.) - or to route around a
     * host environment (e.g. a dev server) that's replaced the global `fetch` with something
     * that mishandles the manually-set Content-Length header `generateRequest()` always sends.
     */
    fetch?: FetchLike;
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
     * RFC8188 compliance knob (aes128gcm only):
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
    init: FetchLikeInit;
};
