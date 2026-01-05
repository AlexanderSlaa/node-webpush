'use strict';

export enum SupportedContentEncoding {
    AES_GCM = 'aesgcm',
    AES_128_GCM = 'aes128gcm',
}

export enum SupportedUrgency {
    VERY_LOW = 'very-low',
    LOW = 'low',
    NORMAL = 'normal',
    HIGH = 'high',
}

/** Default TTL is 4 weeks (seconds). */
export const DEFAULT_TTL = 2419200;

/**
 * Default record size (RFC8188 `rs`) for aes128gcm.
 * For Web Push (RFC8291), a single record is required, but `rs` still appears in the body header.
 */
export const DEFAULT_RS = 4096;

/** Minimum valid `rs` for aes128gcm per RFC8188 (must be >= 18). */
export const MIN_RS = 18;
