'use strict';

export const base64url = {
    validate(input: string): boolean {
        // URL-safe base64 without "=" padding
        return /^[A-Za-z0-9\-_]+$/.test(input);
    },
    toBuffer(input: string): Buffer {
        return Buffer.from(input, 'base64url');
    },
    toString(input: Buffer | Uint8Array | string): string {
        const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);
        return buf.toString('base64url');
    },
    toJSON(obj: any) {
        return this.toString(Buffer.from(JSON.stringify(obj), 'utf8'));
    }
};
