'use strict';

// Run: npx tsx examples/server/send-notification.ts
//
// Minimal standalone example: sends a push notification via webpush.notify(),
// which does the fetch() for you. Needs VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY
// (see generate-vapid-keys.ts) and a real subscription object from a browser's
// PushManager.subscribe() (see server.ts for a full client+server example that
// captures real subscriptions).

import {WebPush, type PushSubscription} from '../../src/index.js';

const webpush = new WebPush({
    vapid: {
        subject: 'mailto:admin@example.com',
        publicKey: process.env.VAPID_PUBLIC_KEY!,
        privateKey: process.env.VAPID_PRIVATE_KEY!,
    },
});

// Replace with a real subscription from the browser (PushManager.subscribe()).
const subscription: PushSubscription = {
    endpoint: 'https://push-service.example/subscription-id',
    keys: {
        p256dh: '<base64url p256dh from the subscription>',
        auth: '<base64url auth secret from the subscription>',
    },
};

const res = await webpush.notify(subscription, JSON.stringify({title: 'Hello!', body: 'This is a push message.'}), {
    TTL: 60,
});

console.log('Status:', res.status);
