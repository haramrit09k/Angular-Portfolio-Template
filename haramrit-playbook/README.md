# Compass

A personal, offline-first operating manual: a dashboard, situational
protocols, decision trees, a weekly review, and time-boxed experiments —
behind a PIN lock. Static site, no backend, no build tooling, no external
fonts/CDN/analytics/tracking.

## First-time setup

1. Copy the example content file and edit it with your real content:
   ```
   cp scripts/content.example.json scripts/content.json
   ```
   `scripts/content.json` is gitignored — it never gets committed. Only the
   encrypted output (`data.js`) does.

2. Generate `data.js`:
   ```
   node scripts/build-content.js
   ```
   You'll be prompted for a 4 or 6 digit PIN (run this in a private
   terminal — it's typed in plain sight, Node doesn't mask stdin by
   default). This encrypts `content.json` and writes `data.js`.

   The repo ships with **placeholder demo content and a demo PIN (`1234`)**
   for scaffolding only. Regenerate both before real use.

3. (Optional) Regenerate icons, only if you change the accent color or the
   mark itself:
   ```
   python3 scripts/generate-icons.py
   ```

## Threat model — read this honestly

- **What this protects against:** casual snooping. Without the PIN, the
  lock screen blocks the UI, and `data.js` itself is unreadable — it's
  AES-256-GCM ciphertext, not plaintext protocol text, so opening dev
  tools / view-source / the Network tab doesn't reveal the content either.
- **What this does not protect against:** someone who has your PIN, or a
  determined attacker who obtains `data.js` and brute-forces it offline.
  The salt, IV, ciphertext, and iteration count all ship in that file, so
  there's no way to rate-limit or lock out offline guesses — a 4-digit PIN
  (10,000 combinations) is brute-forceable in well under an hour even at
  300,000 PBKDF2 iterations; 6 digits (1,000,000 combinations) is
  meaningfully better but still not safe against a truly determined
  attacker with the file in hand. **Prefer a 6-digit PIN.**
- Decrypted content lives in memory only for the life of the page — it is
  never written to localStorage/sessionStorage.

## Editing content later

Edit `scripts/content.json`, then re-run:
```
node scripts/build-content.js
```
and **bump `CACHE_VERSION` in `sw.js`** — the service worker is
cache-first, so that's the only thing that makes already-installed users
pick up the change.

## Local preview

Any static file server works. Plain `file://` won't reliably register the
service worker, so use http(s):
```
python3 -m http.server 8080
# or: npx serve .
```
Then open `http://localhost:8080`.

## Deploying (e.g. Netlify), no backend

- New site from Git.
- Base directory / publish directory: `haramrit-playbook`.
- Build command: none — it's static.
- No `netlify.toml` is required (hash-based routing needs no server
  rewrite rules). Optionally add one just to set
  `Cache-Control: no-cache` on `sw.js` so browsers always re-check for
  updates before falling back to cache-first.

## Face ID / Touch ID (WebAuthn)

Optional, additive, per-device. Offered from **Settings** after you've
unlocked with the real PIN on that device at least once — a device that
has never seen the real PIN can never use biometrics to get in.

Two modes, shown in Settings as a status pill:
- **`prf`** — the browser supports the WebAuthn PRF extension, which
  genuinely wraps your content decryption key. Strong.
- **`assertion-gate`** — PRF isn't supported on that device/browser, so a
  successful Face ID/Touch ID prompt just gates reading a key that's
  stored locally. Weaker than the PIN; treat it as a convenience, not a
  security upgrade, on those devices.

If the device has no platform authenticator at all, no biometric UI is
shown anywhere.

## File structure

```
haramrit-playbook/
├── index.html              Lock screen + app shell
├── styles.css               All styling
├── app.js                    All logic (crypto, store, router, views, WebAuthn)
├── data.js                   GENERATED — crypto constants only, no plaintext
├── manifest.json              PWA manifest
├── sw.js                       Service worker (cache-first, versioned)
├── icons/                      icon.svg + generated PNGs
└── scripts/
    ├── build-content.js        content.json -> data.js
    ├── generate-icons.py       Icon generator (pure stdlib, no PIL)
    ├── content.example.json    Committed — schema reference, placeholders only
    └── content.json             GITIGNORED — your real content
```

## Manual testing checklist

- [ ] Lock screen shows by default; wrong PIN shakes and clears, no content leak.
- [ ] Correct PIN unlocks and shows real content.
- [ ] `data.js` is unreadable ciphertext when inspected directly in dev tools.
- [ ] All routes work: dashboard, quick actions → each protocol, known
      bugs, each decision tree to a recommendation, weekly review updates
      the score, each experiment's day-tracker.
- [ ] Reload while offline (airplane mode / dev tools offline) — app
      shell still loads.
- [ ] `manifest.json` is valid and icons load (dev tools → Application).
- [ ] Install to home screen on a phone.
- [ ] On a WebAuthn-capable device: enroll Face ID/Touch ID in Settings,
      lock, and quick-unlock with it.
- [ ] On a non-biometric browser: confirm no biometric UI appears anywhere.
