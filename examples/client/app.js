// Client-side flow: register the service worker, subscribe with PushManager
// using the server's VAPID public key, then hand the subscription to the server.
// Talks to the plain-Node server in ../server/server.ts.

function base64UrlToUint8Array(base64Url) {
    const padding = '='.repeat((4 - (base64Url.length % 4)) % 4);
    const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(base64);
    return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

const subscribeButton = document.getElementById('subscribe');
const notifyButton = document.getElementById('notify');
const statusEl = document.getElementById('status');

function setStatus(text) {
    statusEl.textContent = text;
}

subscribeButton.addEventListener('click', async () => {
    try {
        const registration = await navigator.serviceWorker.register('sw.js');

        const permission = await Notification.requestPermission();
        if (permission !== 'granted') {
            setStatus('Notification permission denied.');
            return;
        }

        const {publicKey} = await fetch('/vapid-public-key').then((r) => r.json());

        const subscription = await registration.pushManager.subscribe({
            userVisibleOnly: true,
            applicationServerKey: base64UrlToUint8Array(publicKey),
        });

        await fetch('/subscribe', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(subscription),
        });

        setStatus('Subscribed. You can now send a test push.');
        notifyButton.disabled = false;
    } catch (err) {
        setStatus('Error: ' + err.message);
    }
});

notifyButton.addEventListener('click', async () => {
    const res = await fetch('/notify', {method: 'POST'});
    setStatus(res.ok ? 'Push sent, check your notifications.' : 'Push failed: ' + res.status);
});
