<div align="center">

```
   ▄████████  ▄█   ▄████████  ▄██████▄  ▄████████
  ███    ███ ███  ███    ███ ███    ███ ███    ███
  ███    █▀  ███▌ ███    █▀  ███    ███ ███    █▀
 ▄███▄▄▄     ███▌ ███        ███    ███ ███
▀▀███▀▀▀     ███▌ ▀███████████ ███    ███ ███████████
  ███        ███           ███ ███    ███          ███
  ███        ███  ▄█    ███ ███ ███    ███    ▄█    ███
  █▀         █▀ ▄████████▀   ▀██████▀   ▄████████▀

           D R O P
```

# FluxDrop

### `> zero-knowledge P2P file transfer, engineered for privacy`

[![License: MIT](https://img.shields.io/badge/license-MIT-00ff9f.svg?style=for-the-badge)](LICENSE)
[![WebRTC](https://img.shields.io/badge/transport-WebRTC-00ff9f.svg?style=for-the-badge)](#)
[![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-00ff9f.svg?style=for-the-badge)](#)
[![Key Exchange](https://img.shields.io/badge/key_exchange-ECDH_P--256-00ff9f.svg?style=for-the-badge)](#)
[![No Server Storage](https://img.shields.io/badge/server_storage-NONE-ff0055.svg?style=for-the-badge)](#)

**Your files never touch a server. Not once. Not ever.**

</div>

---

## `[ 0x00 ]` OVERVIEW

FluxDrop is a browser-based, peer-to-peer file transfer system built for people
who don't trust the cloud with their data — and shouldn't have to. Two devices
pair over a scannable QR handshake, derive a shared encryption key entirely on
their own hardware, and stream files directly to each other over an encrypted
WebRTC channel. No uploads. No accounts. No middleman with a copy of your file.

If a signaling server goes down mid-transfer, it doesn't matter — by then it's
already been cut out of the loop.

```
[ SENDER ]  <---- ECDH key exchange via animated QR ---->  [ RECEIVER ]
     |                                                            |
     '-------------- direct encrypted WebRTC channel -------------'
                    (signaling server no longer involved)
```

---

## `[ 0x01 ]` CORE CAPABILITIES

| Capability | Implementation |
|---|---|
| 🔐 End-to-end encryption | `AES-256-GCM`, unique IV per chunk |
| 🤝 Key exchange | `ECDH P-256` — keys are derived, never transmitted |
| 📡 Transport | `WebRTC` `RTCDataChannel`, direct device-to-device |
| 📷 Pairing | Animated multi-frame QR handshake, no typing IPs |
| 🧠 Streaming | 64KB chunked reads — handles files of any size |
| ✅ Integrity | `SHA-256` hash verification on completion |
| 🚫 Accounts | None. No signup, no login, no tracking |
| 🌐 Access | Any device with a modern browser + camera |

---

## `[ 0x02 ]` HOW THE HANDSHAKE WORKS

```
1. INITIALIZE   sender generates ECDH P-256 keypair
                 public key -> chunked -> animated QR frames

2. PAIR          receiver's camera scans QR sequence
                 both sides independently derive the SAME AES-256 key
                 (the key itself never crosses the wire)

3. CONNECT       WebRTC offer/answer + ICE candidates exchanged
                 via a lightweight WebSocket signaling server
                 direct encrypted data channel opens
                 signaling server steps out of the picture

4. TRANSFER      file streamed in 64KB chunks
                 each chunk: random 12-byte IV + AES-256-GCM
                 receiver decrypts + reassembles + verifies SHA-256

5. DELIVER       receiver downloads the file, byte-for-byte
```

---

## `[ 0x03 ]` STACK

**Client** — Vanilla HTML5 / CSS3 / JS. No frameworks, no build step.
`WebRTC` · `WebCrypto` · `MediaDevices` (camera) · QR generation & scanning

**Server** — `Node.js` + `ws`. A signaling relay only — it brokers
connection metadata (offers, answers, ICE candidates) and never sees file
data or encryption keys.

**Infra** — Optional `Cloudflare Tunnel` for HTTPS, since WebCrypto and
camera access require a secure context on mobile.

---

## `[ 0x04 ]` WHY THESE DECISIONS

- **Peer-to-peer over server relay** — files never sit on a disk you don't
  control, and there's no bandwidth bottleneck to pay for or scale.
- **QR pairing over manual IP entry** — secure key exchange without ever
  routing key material through the server.
- **Streaming over buffering** — a device only ever holds 64KB of a file in
  memory at once, so file size is bounded by patience, not RAM.
- **ECDH + AES-256-GCM** — forward secrecy (each session's key exchange is
  independent) plus authenticated encryption (tampering is detected, not
  just blocked).

---

## `[ 0x05 ]` RUN IT LOCALLY

```bash
# clone
git clone https://github.com/realnishil/FluxDrop.git
cd FluxDrop

# install
npm install
cd server && npm install && cd ..

# start
node server/server.js
# -> serving on http://localhost:4000

# optional: expose over HTTPS for mobile testing
npx cloudflared tunnel --config cloudflared.yml
```

| Route | Purpose |
|---|---|
| `/` | Landing page |
| `/app` | Send / receive interface |

**Requirements:** Node.js v14+, a browser with camera access for QR scanning.

---

## `[ 0x06 ]` PROJECT LAYOUT

```
FluxDrop/
├── client/
│   ├── index.html      # send / receive interface
│   ├── home.html        # landing page
│   ├── app.js            # client logic — crypto, WebRTC, QR
│   ├── style.css / home.css
│   ├── qrcode.min.js     # QR generation
│   └── zxing.min.js      # QR scanning (camera)
├── server/
│   ├── server.js         # WebSocket signaling + static file server
│   └── package.json
├── cloudflared.yml        # Cloudflare Tunnel config
└── package.json
```

---

## `[ 0x07 ]` SECURITY MODEL

- Files are encrypted **before** they ever leave the sender's device.
- The signaling server only ever sees connection metadata — offers,
  answers, ICE candidates. It cannot see file contents or keys.
- Each session generates a fresh ECDH keypair — compromise of one
  session's key has no bearing on any other session (forward secrecy).
- Every chunk gets its own random IV, preventing pattern analysis across
  a file's ciphertext.
- The WebSocket server validates message shape, room IDs, and roles, and
  drops dead connections via heartbeat monitoring.

This is a personal/portfolio-grade implementation demonstrating these
primitives correctly — it has not undergone a third-party security audit.
Treat it accordingly if you're relying on it for anything sensitive.

---

## `[ 0x08 ]` ROADMAP

- [ ] Streaming hash computation for very large (2GB+) files
- [ ] Batch / multi-file transfers
- [ ] Transfer pause & resume
- [ ] Reliable-mode data channel option
- [ ] Multi-peer group transfers
- [ ] E2EE chat alongside file transfer

---

<div align="center">

### `> built by Nishil,Naitik,Aastik — cybersecurity `

[GitHub](https://github.com/realnishil) · [X/Twitter](https://x.com/notnishil) · [LinkedIn](https://linkedin.com/in/nishilbhimani)

**License:** [MIT](LICENSE)

</div>
