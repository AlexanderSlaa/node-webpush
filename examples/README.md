# Examples

Run any `.ts` file directly with [`tsx`](https://github.com/privatenumber/tsx) (already a devDependency):

```bash
npx tsx examples/server/generate-vapid-keys.ts
```

These examples import from `../../src/index.js` (the local source), so they run
against your working copy of the library without a build step. In your own
project, import from `"node-webpush"` instead — see the root [README](../README.md).

## server/ — Node.js, sending pushes

- **`generate-vapid-keys.ts`** — prints a VAPID key pair. Run once, save the output.
- **`send-notification.ts`** — minimal `webpush.notify(...)` call with a hardcoded subscription.
- **`manual-fetch.ts`** — `generateRequest()` + your own `fetch()` call, for custom HTTP stacks.
- **`error-handling.ts`** — catching `WebPushError` and reading the push service's response status.
- **`server.ts`** — a small full server (no framework) that serves `../client`, hands out the
  VAPID public key, stores subscriptions posted by the browser, and sends a test push.

Set these env vars before running anything that sends a real push:

```bash
export VAPID_PUBLIC_KEY=...
export VAPID_PRIVATE_KEY=...
```

(`server.ts` generates a throwaway pair for you if these aren't set, so it works standalone.)

## client/ — browser, subscribing and receiving pushes

- **`index.html`** — a page with "Subscribe" / "Send test push" buttons.
- **`app.js`** — registers the service worker, calls `PushManager.subscribe()`, posts the
  resulting subscription to the server.
- **`sw.js`** — the service worker; handles the `push` event and shows a notification.

These aren't meant to run standalone — they're served by `server/server.ts`.

## Try the full flow

```bash
npx tsx examples/server/server.ts
```

Open `http://localhost:3000`, click **Subscribe to push** (grant the notification
permission prompt), then **Send test push**. The Push API requires HTTPS in
production, but `localhost` is exempted so this works over plain HTTP for local testing.
