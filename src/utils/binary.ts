'use strict';

/** Write UInt16BE. */
export function u16be(n: number): Buffer {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(n, 0);
    return b;
}

/** Write UInt32BE. */
export function u32be(n: number): Buffer {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n >>> 0, 0);
    return b;
}

export function xorBytes(a: Buffer, b: Buffer): Buffer {
    if (a.length !== b.length) throw new Error('xorBytes: length mismatch');
    const out = Buffer.alloc(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
}

/**
 * Convert a record sequence number into a 96-bit (12-octet) big-endian buffer.
 * RFC8188 defines SEQ as a 96-bit unsigned integer starting at 0.
 */
export function seq96be(seq: number): Buffer {
    if (!Number.isSafeInteger(seq) || seq < 0) throw new Error('SEQ must be a non-negative safe integer');
    const out = Buffer.alloc(12, 0x00);

    // Write into low 64 bits; high 32 bits remain zero.
    const hi = Math.floor(seq / 0x100000000);
    const lo = seq >>> 0;
    out.writeUInt32BE(hi >>> 0, 4);
    out.writeUInt32BE(lo, 8);
    return out;
}
