// Service worker: receives the push event and shows a notification.
// Runs in the browser, registered by app.js via navigator.serviceWorker.register('sw.js').

self.addEventListener('push', (event) => {
    let data = {title: 'Push', body: ''};
    try {
        data = event.data.json();
    } catch {
        data.body = event.data ? event.data.text() : '';
    }

    event.waitUntil(
        self.registration.showNotification(data.title, {
            body: data.body,
            icon: data.icon,
        })
    );
});
