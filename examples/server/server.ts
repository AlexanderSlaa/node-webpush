'use strict';

// Run: npx tsx examples/server/server.ts
// Then open http://localhost:3000 in a browser (or localhost over HTTP is fine
// for the Push API; a real deployment needs HTTPS).
//
// Full client+server flow:
//   1. Serves ../client (index.html, app.js, sw.js).
//   2. GET  /vapid-public-key -> the VAPID public key the client subscribes with.
//   3. POST /subscribe        -> stores the PushSubscription the browser sends back.
//   4. POST /notify           -> pushes a test notification to every stored subscription.
//
// Uses only Node's built-in http/fs (no framework) so the example has no extra deps.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {WebPush, WebPushError, type PushSubscription} from '../../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const clientDir = path.join(__dirname, '..', 'client');

let vapidKeys = {
    publicKey: process.env.VAPID_PUBLIC_KEY,
    privateKey: process.env.VAPID_PRIVATE_KEY,
};

if (!vapidKeys.publicKey || !vapidKeys.privateKey) {
    console.warn('No VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY set; generating a throwaway pair for this run.');
    console.warn('Run examples/server/generate-vapid-keys.ts to get a pair you can reuse.');
    const {VAPID} = await import('../../src/index.js');
    vapidKeys = VAPID.GenerateKeys();
}

const webpush = new WebPush({
    vapid: {
        subject: 'mailto:admin@example.com',
        publicKey: vapidKeys.publicKey!,
        privateKey: vapidKeys.privateKey!,
    },
});

// In-memory only: swap for a real database in production.
const subscriptions: PushSubscription[] = [];

function readJsonBody(req: http.IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
        let raw = '';
        req.on('data', (chunk) => (raw += chunk));
        req.on('end', () => {
            try {
                resolve(raw ? JSON.parse(raw) : {});
            } catch (err) {
                reject(err);
            }
        });
        req.on('error', reject);
    });
}

const MIME: Record<string, string> = {
    '.html': 'text/html',
    '.js': 'text/javascript',
};

function serveStatic(req: http.IncomingMessage, res: http.ServerResponse): boolean {
    const urlPath = req.url === '/' ? '/index.html' : req.url ?? '/index.html';
    const filePath = path.join(clientDir, urlPath);

    if (!filePath.startsWith(clientDir) || !fs.existsSync(filePath)) return false;

    const ext = path.extname(filePath);
    res.writeHead(200, {'Content-Type': MIME[ext] ?? 'application/octet-stream'});
    res.end(fs.readFileSync(filePath));
    return true;
}

const server = http.createServer(async (req, res) => {
    try {
        if (req.method === 'GET' && req.url === '/vapid-public-key') {
            res.writeHead(200, {'Content-Type': 'application/json'});
            res.end(JSON.stringify({publicKey: vapidKeys.publicKey}));
            return;
        }

        if (req.method === 'POST' && req.url === '/subscribe') {
            const subscription = (await readJsonBody(req)) as PushSubscription;
            subscriptions.push(subscription);
            res.writeHead(201);
            res.end();
            return;
        }

        if (req.method === 'POST' && req.url === '/notify') {
            const payload = JSON.stringify({title: 'Hello!', body: 'This is a push message.'});

            const results = await Promise.allSettled(
                subscriptions.map((subscription) =>
                    webpush.notify(subscription, payload, {throwOnInvalidResponse: true})
                )
            );

            for (const result of results) {
                if (result.status === 'rejected' && result.reason instanceof WebPushError) {
                    console.error('Push failed:', result.reason.response.status);
                }
            }

            res.writeHead(200);
            res.end();
            return;
        }

        if (req.method === 'GET' && serveStatic(req, res)) return;

        res.writeHead(404);
        res.end('Not found');
    } catch (err) {
        console.error(err);
        res.writeHead(500);
        res.end('Internal error');
    }
});

const port = Number(process.env.PORT ?? 3000);
server.listen(port, () => {
    console.log(`Listening on http://localhost:${port}`);
});
