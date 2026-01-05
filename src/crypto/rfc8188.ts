'use strict';

import crypto from 'crypto';
import { MIN_RS } from '../constants';
import { xorBytes, seq96be } from '../utils/binary';

/**
 * Build RFC8188 plaintext records from message bytes.
 *
 * Record plaintext length for full records is `rs - 16` because AES-GCM adds a 16-byte tag.
 * The padding delimiter must be present in every record:
 * - 0x01 for all non-last records
 * - 0x02 for the last record
 */
export function buildPlaintextRecords(params: {
    message: Buffer;
    rs: number;
    allowMultipleRecords: boolean;
    finalRecordPadding: number;
}): Buffer[] {
    const { message, rs, allowMultipleRecords, finalRecordPadding } = params;

    if (!Number.isInteger(rs) || rs < MIN_RS) {
        throw new Error(`Invalid rs; must be an integer >= ${MIN_RS}.`);
    }

    const maxPlain = rs - 16; // AES-GCM tag length is 16
    if (maxPlain <= 1) throw new Error('Invalid rs (too small)');

    const maxDataPerFullRecord = maxPlain - 1; // reserve delimiter

    if (!allowMultipleRecords && message.length > maxDataPerFullRecord) {
        throw new Error(
            `Payload too large for a single RFC8188 record: ${message.length} bytes. ` +
            `Max is ${maxDataPerFullRecord} bytes for rs=${rs}.`
        );
    }

    if (!Number.isInteger(finalRecordPadding) || finalRecordPadding < 0) {
        throw new Error('finalRecordPadding must be a non-negative integer');
    }

    const records: Buffer[] = [];
    let offset = 0;

    while (offset < message.length) {
        const remaining = message.length - offset;
        const isLast = remaining <= maxDataPerFullRecord;

        const dataLen = isLast ? remaining : maxDataPerFullRecord;
        const data = message.subarray(offset, offset + dataLen);
        offset += dataLen;

        const delimiter = Buffer.from([isLast ? 0x02 : 0x01]);

        if (!isLast) {
            // Full-sized non-last record.
            const paddingLen = maxPlain - (data.length + 1);
            records.push(Buffer.concat([data, delimiter, Buffer.alloc(paddingLen, 0x00)]));
        } else {
            // Last record can be partial and may include padding after delimiter.
            records.push(Buffer.concat([data, delimiter, Buffer.alloc(finalRecordPadding, 0x00)]));
        }
    }

    // Empty message -> final record with only delimiter (0x02)
    if (message.length === 0) records.push(Buffer.from([0x02]));

    return records;
}

/**
 * Encrypt RFC8188 plaintext records using AES-128-GCM.
 *
 * Nonce per record: nonce = baseNonce XOR SEQ (96-bit big-endian SEQ starting at 0).
 * AAD is empty.
 */
export function encryptRecords(params: {
    cek: Buffer;       // 16 bytes
    baseNonce: Buffer; // 12 bytes
    plaintextRecords: Buffer[];
}): Buffer {
    const { cek, baseNonce, plaintextRecords } = params;
    if (cek.length !== 16) throw new Error('CEK must be 16 bytes');
    if (baseNonce.length !== 12) throw new Error('baseNonce must be 12 bytes');

    const out: Buffer[] = [];
    for (let i = 0; i < plaintextRecords.length; i++) {
        const nonce = xorBytes(baseNonce, seq96be(i));
        const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);

        const enc = Buffer.concat([cipher.update(plaintextRecords[i]), cipher.final()]);
        out.push(Buffer.concat([enc, cipher.getAuthTag()]));
    }
    return Buffer.concat(out);
}
