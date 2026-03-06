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

function decodeJwtPayloadFromAuthorization(authorization: string): Record<string, unknown> {
    const token = authorization.startsWith("vapid t=")
        ? authorization.slice("vapid t=".length).split(", k=")[0]
        : authorization.startsWith("WebPush ")
          ? authorization.slice("WebPush ".length)
          : "";

    if (!token) throw new Error("Unsupported authorization header format");

    const parts = token.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");

    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

describe("Endpoint integration behavior", () => {
    it("uses VAPID for FCM endpoints when VAPID details are configured", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://fcm.googleapis.com/fcm/send/abc");

        const { init } = wp.generateRequest(sub, "hello", {
            contentEncoding: SupportedContentEncoding.AES_128_GCM,
        });

        const headers = init.headers as Record<string, string>;
        expect(headers["Authorization"]?.startsWith("vapid t=")).toBe(true);

        const payload = decodeJwtPayloadFromAuthorization(headers["Authorization"]);
        expect(payload.aud).toBe("https://fcm.googleapis.com");
    });

    it("falls back to API key for FCM endpoint when VAPID is explicitly disabled", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://fcm.googleapis.com/fcm/send/abc");

        const { init } = wp.generateRequest(sub, "hello", {
            vapidDetails: null,
            gcmAPIKey: "my-fcm-key",
            contentEncoding: SupportedContentEncoding.AES_128_GCM,
        });

        const headers = init.headers as Record<string, string>;
        expect(headers["Authorization"]).toBe("key=my-fcm-key");
    });

    it("uses VAPID for Mozilla autopush endpoints and sets audience to endpoint origin", () => {
        const wp = makeWebPush();
        const sub = makeValidSubscription("https://updates.push.services.mozilla.com/wpush/v2/abc");

        const { init } = wp.generateRequest(sub, "hello", {
            contentEncoding: SupportedContentEncoding.AES_128_GCM,
        });

        const headers = init.headers as Record<string, string>;
        expect(headers["Authorization"]?.startsWith("vapid t=")).toBe(true);

        const payload = decodeJwtPayloadFromAuthorization(headers["Authorization"]);
        expect(payload.aud).toBe("https://updates.push.services.mozilla.com");
    });
});
