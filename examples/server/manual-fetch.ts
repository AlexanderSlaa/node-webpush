'use strict';

// Run: npx tsx examples/server/manual-fetch.ts
//
// Use generateRequest() instead of notify() when you want to inspect/modify
// the request or plug it into your own HTTP client instead of fetch().

import {WebPush, type PushSubscription} from '../../src/index.js';

const webpush = new WebPush({
    vapid: {
        subject: 'mailto:admin@example.com',
        publicKey: process.env.VAPID_PUBLIC_KEY!,
        privateKey: process.env.VAPID_PRIVATE_KEY!,
    },
});

const subscription: PushSubscription = {
    endpoint: 'https://push-service.example/subscription-id',
    keys: {
        p256dh: '<base64url p256dh from the subscription>',
        auth: '<base64url auth secret from the subscription>',
    },
};

const {endpoint, init} = webpush.generateRequest(subscription, 'hello', {
    TTL: 120,
    urgency: 'high',
});

console.log('Endpoint:', endpoint);
console.log('Headers:', init.headers);

const res = await fetch(endpoint, init);
console.log('Status:', res.status);
