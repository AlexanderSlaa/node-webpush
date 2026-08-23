'use strict';

// Run: npx tsx examples/server/error-handling.ts
//
// Shows how to catch a rejected push and inspect the push service's response
// (e.g. 404/410 means the subscription is gone and should be deleted).

import crypto from 'node:crypto';
import {WebPush, WebPushError, type PushSubscription} from '../../src/index.js';

const webpush = new WebPush({
    vapid: {
        subject: 'mailto:admin@example.com',
        publicKey: process.env.VAPID_PUBLIC_KEY!,
        privateKey: process.env.VAPID_PRIVATE_KEY!,
    },
});

// A syntactically valid but made-up subscription, so encryption succeeds and we
// get all the way to the (fake, unreachable) push service. Use a real subscription
// from the browser in production.
const ecdh = crypto.createECDH('prime256v1');
ecdh.generateKeys();
const subscription: PushSubscription = {
    endpoint: 'https://push-service.example/subscription-id',
    keys: {
        p256dh: ecdh.getPublicKey().toString('base64url'),
        auth: crypto.randomBytes(16).toString('base64url'),
    },
};

try {
    await webpush.notify(subscription, 'hello', {
        throwOnInvalidResponse: true, // without this, notify() just resolves with the (possibly non-2xx) Response
    });
    console.log('Push sent.');
} catch (err) {
    if (err instanceof WebPushError) {
        console.error('Push service rejected the request:', err.response.status);
        console.error('Response body:', await err.response.text());

        if (err.response.status === 404 || err.response.status === 410) {
            // Subscription is no longer valid — remove it from your database.
            console.log('Subscription expired; delete it from storage.');
        }
    } else {
        // e.g. a network error reaching the push service. The endpoint above is
        // fake and unreachable, so running this example unmodified ends up here.
        console.error('Unexpected error:', (err as Error).message);
    }
}
