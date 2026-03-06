import { describe, it, expect } from "vitest";
import crypto from "crypto";

import { WebPush, VAPID, SupportedContentEncoding, type PushSubscription } from "../src";

function makeValidSubscription(endpoint: string): PushSubscription {
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.generateKeys();

    return {
        endpoint,
        keys: {
            p256dh: ecdh.getPublicKey().toString("base64url"),
            auth: crypto.randomBytes(16).toString("base64url"),
        },
    };
}

function makeWebPush() {
    const vapidKeys = VAPID.GenerateKeys();
    return new WebPush({
        vapid: {
            subject: "mailto:test@example.com",
            publicKey: vapidKeys.publicKey,
            privateKey: vapidKeys.privateKey,
        },
        gcm: { apiKey: "test-gcm-key" },
    });
}

describe("Negative and security regression cases", () => {
    it("rejects empty GCM/FCM API keys in constructor", () => {
        const vapidKeys = VAPID.GenerateKeys();

        expect(
            () =>
                new WebPush({
                    vapid: {
                        subject: "mailto:test@example.com",
                        publicKey: vapidKeys.publicKey,
                        privateKey: vapidKeys.privateKey,
                    },
                    gcm: { apiKey: "" },
                })
        ).toThrow(/non-empty string/i);
    });

    it("rejects invalid TTL and rs values", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://example.com/push");

        expect(() => wp.generateRequest(sub, "hello", { TTL: -1 })).toThrow(/TTL/i);
        expect(() =>
            wp.generateRequest(sub, "hello", {
                contentEncoding: SupportedContentEncoding.AES_128_GCM,
                rs: 17,
            })
        ).toThrow(/rs/i);
    });

    it("rejects payload sends without required subscription keys", () => {
        const wp = makeWebPush();
        const sub: PushSubscription = { endpoint: "https://example.com/push" };

        expect(() => wp.generateRequest(sub, "hello")).toThrow(/keys\.p256dh/i);
    });

    it("does not leak API key auth to non-FCM endpoints when VAPID is disabled", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://example.com/push");

        const { init } = wp.generateRequest(sub, "hello", {
            vapidDetails: null,
            gcmAPIKey: "should-not-be-used",
            contentEncoding: SupportedContentEncoding.AES_128_GCM,
        });

        const headers = init.headers as Record<string, string>;
        expect(headers["Authorization"]).toBeUndefined();
    });

    it("preserves encryption key and appends VAPID key in legacy aesgcm mode", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://example.com/push");

        const { init } = wp.generateRequest(sub, "hello", {
            contentEncoding: SupportedContentEncoding.AES_GCM,
        });

        const headers = init.headers as Record<string, string>;
        expect(headers["Crypto-Key"]).toContain("dh=");
        expect(headers["Crypto-Key"]).toContain("p256ecdsa=");
    });

    it("rejects invalid endpoint URLs when VAPID audience cannot be derived", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("not-a-url");

        expect(() => wp.generateRequest(sub, "hello")).toThrow();
    });

    it("ensures mandatory headers override conflicting user-provided values", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://example.com/push");

        const { init } = wp.generateRequest(sub, "hello", {
            contentEncoding: SupportedContentEncoding.AES_128_GCM,
            headers: {
                Authorization: "attacker-token",
                "Content-Encoding": "plaintext",
                TTL: "999",
            },
            TTL: 60,
        });

        const headers = init.headers as Record<string, string>;
        expect(headers["Authorization"]).not.toBe("attacker-token");
        expect(headers["Content-Encoding"]).toBe("aes128gcm");
        expect(headers["TTL"]).toBe("60");
    });
});
