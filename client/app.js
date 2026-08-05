/**
 * FluxDrop 2.0 - Reliable Encrypted P2P File Transfer Client
 * Vanilla HTML/JS + WebCrypto + WebRTC + WebSocket signaling
 */

// ============================================================
// Configuration
// ============================================================
const CHUNK_SIZE = 64 * 1024;          // 64KB data chunks
const QR_FRAME_INTERVAL = 350;         // ms between QR frames (slower = easier scanning)
const QR_CHUNK_LEN = 100;              // chars per QR frame (smaller = easier scanning)
const MAX_RECONNECT_ATTEMPTS = 5;      // WebSocket reconnect limit
const RECONNECT_DELAY = 2000;          // ms between reconnect attempts

// ============================================================
// Global App State
// ============================================================
const state = {
  ws: null,
  pc: null,
  dc: null,
  role: null,
  roomId: null,
  localKeyPair: null,
  sharedAesKey: null,

  selectedFile: null,
  transferring: false,

  receivedChunks: [],
  receivedFileInfo: null,
  receivedBuffer: null,

  transferredBytes: 0,
  lastSpeedTime: 0,
  lastSpeedBytes: 0,
  currentSpeed: 0,

  animatedInterval: null,
  qrFrames: null,
  cameraReader: null,
  cameraStream: null,

  pendingCandidates: [],
  reconnectAttempts: 0,
};

// Freeze QR animation and show "In Connection" overlay
function freezeQRAnimation() {
  if (state.animatedInterval) {
    clearInterval(state.animatedInterval);
    state.animatedInterval = null;
  }
  const overlay = $('qr-connected-overlay');
  if (overlay) overlay.classList.remove('hidden');
}

// Resume QR animation after connection lost
function resumeQRAnimation() {
  const overlay = $('qr-connected-overlay');
  if (overlay) overlay.classList.add('hidden');

  if (!state.qrFrames || state.qrFrames.length === 0) return;

  let currentIdx = 0;
  if (state.animatedInterval) clearInterval(state.animatedInterval);
  state.animatedInterval = setInterval(() => {
    renderQRToCanvas($('qr-canvas'), state.qrFrames[currentIdx]);
    $('frame-counter').innerText = `Frame ${currentIdx + 1}/${state.qrFrames.length}`;
    currentIdx = (currentIdx + 1) % state.qrFrames.length;
  }, QR_FRAME_INTERVAL);
}

// ============================================================
// UI Helpers
// ============================================================
function $(id) { return document.getElementById(id); }

function showToast(message, type = 'info') {
  let toast = $('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    toast.className = 'toast';
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.className = `toast show toast-${type}`;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove('show'), 4000);
}

function updateSignalBadge(status) {
  const badge = $('signal-badge');
  const text = $('signal-text');
  if (status === 'online') {
    badge.className = 'badge status-online';
    text.innerText = 'Connected';
  } else if (status === 'connecting') {
    badge.className = 'badge status-disconnected';
    text.innerText = 'Connecting...';
  } else {
    badge.className = 'badge status-disconnected';
    text.innerText = 'Not Connected';
  }
}

// Step indicator helpers
function setStepActive(stepId) {
  const el = $(stepId);
  if (el) {
    el.classList.remove('done');
    el.classList.add('active');
  }
}

function setStepDone(stepId) {
  const el = $(stepId);
  if (el) {
    el.classList.remove('active');
    el.classList.add('done');
  }
}

function resetSteps(prefix) {
  for (let i = 1; i <= 3; i++) {
    const el = $(`${prefix}-step-${i}`);
    if (el) {
      el.classList.remove('active', 'done');
      if (i === 1) el.classList.add('active');
    }
  }
}

// ============================================================
// 1. Cryptography Helpers (Web Crypto API)
// ============================================================
async function ensureCryptoAvailable() {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error(
      'Web Cryptography is unavailable.\n\n' +
      'Browsers restrict crypto APIs to Secure Contexts (HTTPS or http://localhost).\n' +
      'Use the Cloudflare HTTPS tunnel link or access via https:// on this device.'
    );
  }
}

async function generateKeyPair() {
  await ensureCryptoAvailable();
  const keyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
  const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return { publicKeyJwk, privateKey: keyPair.privateKey };
}

async function deriveSharedKey(privateKey, remoteJwk) {
  const remotePublicKey = await window.crypto.subtle.importKey(
    'jwk', remoteJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []
  );
  return window.crypto.subtle.deriveKey(
    { name: 'ECDH', public: remotePublicKey },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function sha256(buffer) {
  const digest = await window.crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ============================================================
// 2. Animated QR Protocol (Encoder & Decoder)
// ============================================================
function encodeToFrames(payload) {
  const jsonStr = JSON.stringify(payload);
  const base64Str = btoa(jsonStr);
  const total = Math.ceil(base64Str.length / QR_CHUNK_LEN);
  const frames = [];

  for (let i = 0; i < total; i++) {
    const slice = base64Str.slice(i * QR_CHUNK_LEN, (i + 1) * QR_CHUNK_LEN);
    frames.push(JSON.stringify({
      seq: i + 1,
      total,
      id: payload.sessionId.slice(0, 6),
      data: slice
    }));
  }
  return frames;
}

// Render QR code to canvas using qrcode-generator library
function renderQRToCanvas(canvas, text) {
  try {
    if (typeof qrcode === 'undefined') {
      console.error('qrcode library not loaded');
      return;
    }
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    const ctx = canvas.getContext('2d');
    const size = 220;
    const cellSize = Math.floor(size / qr.getModuleCount());
    const margin = 2;
    const qrSize = qr.getModuleCount() * cellSize;
    const offset = Math.floor((size - qrSize) / 2);

    canvas.width = size;
    canvas.height = size;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000000';

    for (let r = 0; r < qr.getModuleCount(); r++) {
      for (let c = 0; c < qr.getModuleCount(); c++) {
        if (qr.isDark(r, c)) {
          ctx.fillRect(offset + c * cellSize, offset + r * cellSize, cellSize, cellSize);
        }
      }
    }
  } catch (err) {
    console.error('QR render error:', err);
  }
}

class QRReconstructor {
  constructor() {
    this.frames = new Map();
    this.total = 0;
    this.id = '';
  }

  addFrame(raw) {
    try {
      const parsed = JSON.parse(raw);
      if (!parsed.seq || !parsed.total || !parsed.data) return { success: false, progress: 0 };

      // If a new session starts, clear old frames
      if (this.id && this.id !== parsed.id) {
        this.frames.clear();
        this.total = 0;
      }
      this.id = parsed.id;
      this.total = parsed.total;

      // Ignore out-of-range sequence numbers
      if (parsed.seq < 1 || parsed.seq > this.total) return { success: false, progress: 0 };

      this.frames.set(parsed.seq, parsed.data);
      const progress = Math.round((this.frames.size / this.total) * 100);

      if (this.frames.size === this.total) {
        let combined = '';
        for (let i = 1; i <= this.total; i++) {
          if (!this.frames.has(i)) return { success: false, progress };
          combined += this.frames.get(i);
        }
        const payload = JSON.parse(atob(combined));
        return { success: true, progress: 100, payload };
      }
      return { success: false, progress };
    } catch {
      return { success: false, progress: 0 };
    }
  }
}

// ============================================================
// 3. WebSocket Signaling (with auto-reconnect)
// ============================================================
function getSignalUrl() {
  // The server serves BOTH static files and WebSocket on the same port,
  // so we can derive the WebSocket URL directly from the page URL.
  // This works for localhost, LAN IP, and Cloudflare tunnel (HTTPS).
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.hostname || 'localhost';
  const port = window.location.port;

  // If no explicit port (e.g. Cloudflare tunnel on 443), omit it
  if (!port) {
    return `${protocol}//${host}/signal-ws`;
  }
  return `${protocol}//${host}:${port}/signal-ws`;
}

function connectSignaling(roomId, role) {
  state.roomId = roomId;
  state.role = role;
  state.reconnectAttempts = 0;
  openWebSocket();
}

// Store pending public key to send after WebSocket opens
let pendingPublicKey = null;

function openWebSocket() {
  updateSignalBadge('connecting');

  // Clean up any existing socket
  if (state.ws) {
    state.ws.onopen = state.ws.onmessage = state.ws.onerror = state.ws.onclose = null;
    try { state.ws.close(); } catch {}
  }

  const url = getSignalUrl();
  let ws;

  try {
    ws = new WebSocket(url);
  } catch (err) {
    showToast('Cannot connect to signaling server', 'error');
    updateSignalBadge('offline');
    return;
  }

  state.ws = ws;

  ws.onopen = () => {
    state.reconnectAttempts = 0;
    updateSignalBadge('online');
    ws.send(JSON.stringify({ type: 'join', roomId: state.roomId, role: state.role }));

    // If we have a pending public key (receiver), send it now
    if (pendingPublicKey) {
      ws.send(JSON.stringify({ type: 'public-key', payload: pendingPublicKey }));
      pendingPublicKey = null;
    }

    // Update connection notes
    if (state.role === 'sender') {
      const note = $('sender-connection-note');
      note.classList.remove('hidden');
      note.className = 'connection-note pending';
      $('sender-conn-text').innerText = '⏳ Waiting for receiver to scan your QR...';
    } else {
      const note = $('recv-connection-note');
      note.classList.remove('hidden');
      note.className = 'connection-note pending';
      $('recv-conn-text').innerText = '⏳ Connecting to sender...';
    }
  };

  ws.onmessage = async (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      return;
    }

    switch (msg.type) {
      case 'joined':
        console.log(`[SIG] Joined room ${msg.roomId} as ${msg.role}, peerPresent: ${msg.peerPresent}`);
        break;

      case 'peer-joined':
        $('receiver-peer-status').innerText = 'Peer Connected (awaiting keys...)';
        // Update step indicator and connection note
        if (state.role === 'sender') {
          setStepDone('send-step-1');
          setStepActive('send-step-2');
          const note = $('sender-connection-note');
          note.className = 'connection-note connected';
          $('sender-conn-text').innerText = '✅ Receiver found! Establishing secure connection...';
        } else {
          setStepDone('recv-step-1');
          setStepActive('recv-step-2');
          const note = $('recv-connection-note');
          note.className = 'connection-note connected';
          $('recv-conn-text').innerText = '✅ Paired! Establishing secure connection...';
        }
        break;

      case 'peer-disconnected':
        showToast('Peer disconnected', 'error');
        $('receiver-peer-status').innerText = 'Peer Disconnected';
        break;

      case 'public-key':
        // Receiver sends their ECDH public key → sender derives shared AES key
        if (state.role === 'sender') {
          try {
            state.sharedAesKey = await deriveSharedKey(state.localKeyPair.privateKey, msg.payload);
            console.log('[CRYPTO] Shared AES key derived (sender side)');
            showToast('🔐 Encryption key exchanged!', 'success');
            $('sender-conn-text').innerText = '🔐 Secure connection established! Ready to send.';
            // Freeze QR animation immediately after key exchange
            freezeQRAnimation();
            initiateWebRTCOffer();
          } catch (err) {
            console.error('Key derivation failed:', err);
            showToast('Failed to derive encryption key', 'error');
          }
        }
        break;

      case 'offer':
        if (state.role === 'receiver') await handleWebRTCOffer(msg.payload);
        break;

      case 'answer':
        if (state.role === 'sender') await handleWebRTCAnswer(msg.payload);
        break;

      case 'ice-candidate':
        if (state.pc && msg.payload) {
          try {
            const candidate = new RTCIceCandidate(msg.payload);
            if (state.pc.remoteDescription) {
              await state.pc.addIceCandidate(candidate);
            } else {
              // Buffer candidates until remote description is set
              state.pendingCandidates.push(candidate);
            }
          } catch (err) {
            console.error('addIceCandidate error:', err);
          }
        }
        break;

      case 'error':
        showToast(`Signal error: ${msg.message || 'unknown'}`, 'error');
        break;
    }
  };

  ws.onerror = () => {
    updateSignalBadge('offline');
  };

  ws.onclose = () => {
    updateSignalBadge('offline');
    state.ws = null;

    // Auto-reconnect (only if we have an active session and haven't given up)
    if (state.role && state.roomId && state.reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
      state.reconnectAttempts++;
      console.log(`[SIG] Reconnecting (attempt ${state.reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`);
      setTimeout(openWebSocket, RECONNECT_DELAY);
    } else if (state.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
      showToast('Lost connection to signaling server', 'error');
    }
  };
}

function sendSignal(type, payload) {
  if (state.ws && state.ws.readyState === WebSocket.OPEN) {
    state.ws.send(JSON.stringify({ type, payload }));
    return true;
  }
  return false;
}

// ============================================================
// 4. WebRTC Peer Connection (with ICE candidate buffering)
// ============================================================
function createPeerConnection() {
  // Close any existing PC
  if (state.pc) {
    try { state.pc.close(); } catch {}
  }

  state.pc = new RTCPeerConnection({
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' }
    ]
  });

  state.pendingCandidates = [];

  state.pc.onicecandidate = (e) => {
    if (e.candidate) {
      sendSignal('ice-candidate', e.candidate);
    }
  };

  state.pc.onconnectionstatechange = () => {
    const status = $('receiver-peer-status');
    switch (state.pc.connectionState) {
      case 'connected':
        status.innerText = 'Peer Connected!';
        if (state.role === 'sender') updateSendButtonState();
        break;
      case 'failed':
      case 'disconnected':
        status.innerText = 'Peer Lost';
        showToast('Peer connection lost', 'error');
        if (state.role === 'sender') {
          resumeQRAnimation();
        }
        break;
      case 'closed':
        status.innerText = 'Idle';
        break;
    }
  };

  return state.pc;
}

async function initiateWebRTCOffer() {
  const pc = createPeerConnection();
  const dc = pc.createDataChannel('fluxdrop');
  setupDataChannel(dc);

  try {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    sendSignal('offer', offer);
    console.log('[RTC] Offer sent');
  } catch (err) {
    console.error('createOffer error:', err);
    showToast('Failed to create WebRTC offer', 'error');
  }
}

async function handleWebRTCOffer(offer) {
  const pc = createPeerConnection();

  pc.ondatachannel = (e) => {
    state.dc = e.channel;
    setupDataChannel(state.dc);
  };

  try {
    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    // Flush any buffered ICE candidates
    for (const candidate of state.pendingCandidates) {
      await pc.addIceCandidate(candidate);
    }
    state.pendingCandidates = [];

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    sendSignal('answer', answer);
    console.log('[RTC] Answer sent');
  } catch (err) {
    console.error('handleOffer error:', err);
    showToast('Failed to accept WebRTC offer', 'error');
  }
}

async function handleWebRTCAnswer(answer) {
  if (!state.pc) return;
  try {
    await state.pc.setRemoteDescription(new RTCSessionDescription(answer));
    // Flush any buffered ICE candidates
    for (const candidate of state.pendingCandidates) {
      await state.pc.addIceCandidate(candidate);
    }
    state.pendingCandidates = [];
    console.log('[RTC] Remote description set from answer');
  } catch (err) {
    console.error('handleAnswer error:', err);
    showToast('Failed to apply WebRTC answer', 'error');
  }
}

function setupDataChannel(channel) {
  state.dc = channel;
  channel.binaryType = 'arraybuffer';

  channel.onopen = () => {
    $('receiver-peer-status').innerText = 'Ready for Transfer!';
    if (state.role === 'sender') {
      updateSendButtonState();
      setStepDone('send-step-2');
      setStepActive('send-step-3');
      freezeQRAnimation();
      const note = $('sender-connection-note');
      note.className = 'connection-note connected';
      $('sender-conn-text').innerText = '🔗 Connected! Select a file and send.';
    } else {
      setStepDone('recv-step-2');
      setStepActive('recv-step-3');
      const note = $('recv-connection-note');
      note.className = 'connection-note connected';
      $('recv-conn-text').innerText = '🔗 Connected! Waiting for sender to send a file...';
    }
    showToast('🔗 Secure P2P channel established!', 'success');
  };

  channel.onclose = () => {
    $('receiver-peer-status').innerText = 'Channel Closed';
    state.dc = null;
    if (state.role === 'sender') {
      resumeQRAnimation();
      const note = $('sender-connection-note');
      note.className = 'connection-note pending';
      $('sender-conn-text').innerText = '⚠️ Connection lost! QR resumed for re-pairing...';
    }
  };

  // Queue to ensure chunks are processed in order (prevents race conditions)
  let receiveQueue = Promise.resolve();

  channel.onmessage = (event) => {
    if (typeof event.data === 'string') {
      const meta = JSON.parse(event.data);

      if (meta.type === 'file-start') {
        state.receivedFileInfo = meta.info;
        state.receivedChunks = [];
        state.transferredBytes = 0;
        $('receiver-progress-card').classList.remove('hidden');
        $('receiver-status-text').innerText = 'Receiving Encrypted File...';
      } else if (meta.type === 'file-end') {
        // Wait for all pending chunk decryptions to finish, THEN finalize
        receiveQueue = receiveQueue.then(() => finalizeReceivedFile(meta));
      }
    } else {
      // Encrypted binary chunk - chain onto the queue so decryption happens in order
      receiveQueue = receiveQueue.then(async () => {
        try {
          if (!state.sharedAesKey || !state.receivedFileInfo) return;

          const encryptedData = event.data;
          // First 12 bytes are the random IV
          const iv = new Uint8Array(encryptedData, 0, 12);
          const ciphertext = new Uint8Array(encryptedData, 12);

          const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            state.sharedAesKey,
            ciphertext
          );

          state.receivedChunks.push(new Uint8Array(decrypted));
          state.transferredBytes += decrypted.byteLength;
          updateReceiverProgress(state.transferredBytes, state.receivedFileInfo.size);
        } catch (err) {
          console.error('Decryption error:', err);
          $('receiver-status-text').innerText = '❌ Decryption Failed';
          showToast('Decryption failed - transfer aborted', 'error');
        }
      });
    }
  };
}

// ============================================================
// 5. Sender Workflow
// ============================================================
async function startSenderSession() {
  try {
    await ensureCryptoAvailable();

    // Reset any previous session state
    resetTransferState();

    state.localKeyPair = await generateKeyPair();

    const sessionId = Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
    const sessionPayload = {
      sessionId,
      publicKey: state.localKeyPair.publicKeyJwk,
      timestamp: Date.now()
    };

    // Start rendering animated QR frames
    const frames = encodeToFrames(sessionPayload);
    state.qrFrames = frames;
    let currentIdx = 0;

    $('qr-placeholder').classList.add('hidden');
    $('qr-canvas').classList.remove('hidden');
    $('qr-info').classList.remove('hidden');
    $('qr-connected-overlay').classList.add('hidden');

    if (state.animatedInterval) clearInterval(state.animatedInterval);
    state.animatedInterval = setInterval(() => {
      renderQRToCanvas($('qr-canvas'), frames[currentIdx]);
      $('frame-counter').innerText = `Frame ${currentIdx + 1}/${frames.length}`;
      currentIdx = (currentIdx + 1) % frames.length;
    }, QR_FRAME_INTERVAL);

    // Reset file selection UI
    $('file-input').value = '';
    state.selectedFile = null;
    $('file-label').innerText = 'Click here or drag & drop a file';
    $('file-size').innerText = 'Any file type — Recommended under 2GB for best compatibility';
    $('sender-progress-card').classList.add('hidden');
    $('download-box').classList.add('hidden');
    resetSteps('send');
    $('sender-connection-note').classList.add('hidden');

    // Connect to signaling server
    connectSignaling(sessionId, 'sender');

    showToast('✅ Session started! Share the QR with the receiver.', 'success');
  } catch (err) {
    console.error('startSenderSession error:', err);
    alert(err.message);
  }
}

function handleFileSelect(event) {
  const files = event.target.files;
  if (files && files[0]) {
    setSelectedFile(files[0]);
  }
}

function setSelectedFile(file) {
  state.selectedFile = file;
  $('file-label').innerText = file.name;
  $('file-size').innerText = `${formatSize(file.size)}`;
  updateSendButtonState();
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

// Drag & drop support
function setupDragDrop() {
  const dropZone = $('drop-zone');
  if (!dropZone) return;

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = 'var(--accent-cyan)';
    dropZone.style.background = 'rgba(6, 182, 212, 0.1)';
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.style.borderColor = 'var(--border-color)';
    dropZone.style.background = '';
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = 'var(--border-color)';
    dropZone.style.background = '';
    const files = e.dataTransfer.files;
    if (files && files[0]) {
      setSelectedFile(files[0]);
    }
  });
}

// Initialize drag & drop on page load
document.addEventListener('DOMContentLoaded', setupDragDrop);

function updateSendButtonState() {
  const btn = $('btn-send-file');
  if (state.selectedFile && state.dc && state.dc.readyState === 'open' && state.sharedAesKey) {
    btn.disabled = false;
    btn.innerText = '🚀 Stream Encrypted File';
  } else {
    btn.disabled = true;
    if (!state.selectedFile && state.dc && state.dc.readyState === 'open') {
      btn.innerText = 'Select a file first';
    } else if (!state.sharedAesKey && state.dc && state.dc.readyState === 'open') {
      btn.innerText = 'Exchanging keys...';
    } else {
      btn.innerText = 'Waiting for Receiver...';
    }
  }
}

// ============================================================
// 6. Receiver Workflow (ZXing Camera Scanner)
// ============================================================
async function startScannerCamera() {
  try {
    await ensureCryptoAvailable();

    if (typeof ZXing === 'undefined') {
      alert('QR scanning library failed to load. Please check that zxing.min.js is present.');
      return;
    }

    // Stop any previous scanner
    stopCamera();

    const codeReader = new ZXing.BrowserMultiFormatReader();
    state.cameraReader = codeReader;

    const video = $('scanner-video');
    $('scanner-placeholder').classList.add('hidden');
    video.classList.remove('hidden');

    const reconstructor = new QRReconstructor();
    $('scan-progress-bar').style.width = '0%';
    $('scan-progress-text').innerText = 'Scan Progress: 0%';

    try {
      const devices = await codeReader.listVideoInputDevices();
      const deviceId = devices.length > 0 ? devices[0].deviceId : null;

      codeReader.decodeFromVideoDevice(deviceId, video, (result) => {
        if (result) {
          const raw = result.getText();
          const res = reconstructor.addFrame(raw);

          $('scan-progress-bar').style.width = `${res.progress}%`;
          $('scan-progress-text').innerText = `Scan Progress: ${res.progress}%`;

          if (res.success && res.payload) {
            // Stop camera
            stopCamera();
            $('scanner-placeholder').classList.remove('hidden');
            $('scanner-placeholder').innerHTML = '<p class="success-text">✓ QR Sequence Verified!</p>';
            $('scan-progress-bar').style.width = '100%';
            $('scan-progress-text').innerText = 'Scan Progress: 100%';

            handleScannedPayload(res.payload);
          }
        }
      });
    } catch (err) {
      console.error('Camera error:', err);
      $('scanner-placeholder').classList.remove('hidden');
      $('scanner-placeholder').innerHTML = '<p>Camera permission denied or not available</p>';
      alert('Camera permission denied or camera not available');
    }
  } catch (err) {
    alert(err.message);
  }
}

function stopCamera() {
  if (state.cameraReader) {
    try {
      state.cameraReader.reset();
    } catch {}
    state.cameraReader = null;
  }
  if (state.cameraStream) {
    state.cameraStream.getTracks().forEach((t) => t.stop());
    state.cameraStream = null;
  }
  const video = $('scanner-video');
  if (video) {
    video.classList.add('hidden');
    video.srcObject = null;
  }
}

async function handleScannedPayload(payload) {
  try {
    state.localKeyPair = await generateKeyPair();

    // Derive shared AES key from sender's public key
    state.sharedAesKey = await deriveSharedKey(state.localKeyPair.privateKey, payload.publicKey);
    console.log('[CRYPTO] Shared AES key derived (receiver side)');

    // Connect to signaling
    connectSignaling(payload.sessionId, 'receiver');

    // Queue our public key to send once WebSocket is open
    // (the sender needs it to derive the shared AES key)
    pendingPublicKey = state.localKeyPair.publicKeyJwk;
    console.log('[SIG] Queued public key for sender');

    $('receiver-peer-status').innerText = 'Connected, exchanging keys...';
    $('receiver-progress-card').classList.add('hidden');
    $('download-box').classList.add('hidden');
  } catch (err) {
    console.error('handleScannedPayload error:', err);
    alert('Failed to set up encryption: ' + err.message);
  }
}

// ============================================================
// 7. File Transfer Streaming Logic
// ============================================================
// Stream file in chunks using File.slice() to avoid loading entire file into memory
async function* streamFileChunks(file, chunkSize) {
  let offset = 0;
  while (offset < file.size) {
    const chunk = file.slice(offset, Math.min(offset + chunkSize, file.size));
    const buffer = await chunk.arrayBuffer();
    yield new Uint8Array(buffer);
    offset += buffer.byteLength;
  }
}

// Compute SHA-256 hash
// Note: WebCrypto digest() requires the full buffer, so for very large files
// (>2GB) this may fail due to memory constraints. The transfer itself is streamed.
async function computeHash(file) {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sendSelectedFile() {
  if (!state.selectedFile || !state.dc || state.dc.readyState !== 'open' || !state.sharedAesKey) return;
  if (state.transferring) return;
  state.transferring = true;

  const btn = $('btn-send-file');
  btn.disabled = true;

  const card = $('sender-progress-card');
  card.classList.remove('hidden');
  $('sender-status-text').innerText = 'Hashing file...';
  $('sender-progress-bar').style.width = '0%';
  $('sender-percent-text').innerText = '0%';

  try {
    const file = state.selectedFile;

    // Compute SHA-256 hash for integrity verification
    // Warning: This loads the file into memory. For files >2GB, this may fail.
    let fileHash = null;
    try {
      fileHash = await computeHash(file);
      console.log('[CRYPTO] File SHA-256:', fileHash);
    } catch (err) {
      console.warn('[CRYPTO] Hash computation failed (file too large?), continuing without integrity check');
      showToast('⚠️ File too large for integrity check - transfer will continue', 'info');
    }

    // Send file metadata with hash
    state.dc.send(JSON.stringify({
      type: 'file-start',
      info: { name: file.name, size: file.size, hash: fileHash }
    }));

    $('sender-status-text').innerText = 'Encrypting & Sending...';

    // Stream file in chunks with conservative backpressure
    let offset = 0;
    state.lastSpeedTime = Date.now();
    state.lastSpeedBytes = 0;
    state.currentSpeed = 0;

    // Conservative settings to avoid "queue full" error
    const SEND_DELAY_MS = 5; // Small delay between sends
    const BUFFER_CHECK_THRESHOLD = 512 * 1024; // 512KB - start checking buffer at this level

    for await (const chunk of streamFileChunks(file, CHUNK_SIZE)) {
      // Check buffer before sending - if it's getting full, wait
      if (state.dc.bufferedAmount > BUFFER_CHECK_THRESHOLD) {
        // Buffer is building up, wait for it to drain
        await new Promise((resolve) => {
          const checkBuffer = () => {
            if (state.dc.bufferedAmount < BUFFER_CHECK_THRESHOLD / 2) {
              state.dc.removeEventListener('bufferedamountlow', checkBuffer);
              resolve();
            }
          };
          state.dc.addEventListener('bufferedamountlow', checkBuffer);
          // Fallback: wait max 2 seconds
          setTimeout(() => {
            state.dc.removeEventListener('bufferedamountlow', checkBuffer);
            resolve();
          }, 2000);
        });
      }

      // Random 12-byte IV per chunk
      const iv = window.crypto.getRandomValues(new Uint8Array(12));

      // Encrypt chunk
      const ciphertext = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        state.sharedAesKey,
        chunk
      );

      // Packet = IV (12 bytes) + ciphertext
      const packet = new Uint8Array(iv.length + ciphertext.byteLength);
      packet.set(iv, 0);
      packet.set(new Uint8Array(ciphertext), iv.length);

      state.dc.send(packet.buffer);

      offset += chunk.byteLength;
      updateSenderProgress(offset, file.size);

      // Small delay to prevent overwhelming the buffer
      if (SEND_DELAY_MS > 0) {
        await new Promise((r) => setTimeout(r, SEND_DELAY_MS));
      }
    }

    // Signal completion (include hash if available)
    const endMsg = { type: 'file-end' };
    if (fileHash) endMsg.hash = fileHash;
    state.dc.send(JSON.stringify(endMsg));
    $('sender-status-text').innerText = '✅ Transfer Complete!';
    $('sender-progress-bar').style.width = '100%';
    $('sender-percent-text').innerText = '100%';
    showToast('File sent successfully!', 'success');

  } catch (err) {
    console.error('sendSelectedFile error:', err);
    $('sender-status-text').innerText = '❌ Send Failed';
    showToast('File transfer failed: ' + err.message, 'error');
  } finally {
    state.transferring = false;
  }
}

async function finalizeReceivedFile(meta) {
  try {
    if (!state.receivedChunks.length || !state.receivedFileInfo) return;

    $('receiver-status-text').innerText = 'Verifying integrity...';

    // Combine all chunks
    let totalLength = 0;
    for (const chunk of state.receivedChunks) totalLength += chunk.byteLength;

    const combined = new Uint8Array(totalLength);
    let pos = 0;
    for (const chunk of state.receivedChunks) {
      combined.set(chunk, pos);
      pos += chunk.byteLength;
    }
    state.receivedChunks = [];

    // Verify SHA-256 hash
    const receivedHash = await sha256(combined.buffer);
    const expectedHash = (meta && meta.hash) || (state.receivedFileInfo && state.receivedFileInfo.hash);

    const filesizeEl = $('received-filesize');
    if (filesizeEl) filesizeEl.innerText = formatSize(combined.byteLength);

    if (expectedHash && receivedHash !== expectedHash) {
      console.warn('[INTEGRITY] Hash mismatch!');
      console.warn('  Expected:', expectedHash);
      console.warn('  Received:', receivedHash);
      $('receiver-status-text').innerText = '⚠️ Integrity check warning';
      showToast('Hash mismatch - file may be corrupted', 'error');
      // Still save the file so the user can view/use it
      state.receivedBuffer = combined;
      $('receiver-progress-bar').style.width = '100%';
      $('receiver-percent-text').innerText = '100%';
      $('download-box').classList.remove('hidden');
      $('received-filename').innerText = state.receivedFileInfo.name + ' (unverified)';
      return;
    }

    state.receivedBuffer = combined;
    $('receiver-status-text').innerText = '✅ Transfer Complete!';
    $('receiver-progress-bar').style.width = '100%';
    $('receiver-percent-text').innerText = '100%';
    $('download-box').classList.remove('hidden');
    $('received-filename').innerText = state.receivedFileInfo.name;
    showToast('File received & verified!', 'success');
  } catch (err) {
    console.error('finalizeReceivedFile error:', err);
    $('receiver-status-text').innerText = '❌ Finalization Failed';
    showToast('Failed to finalize received file', 'error');
  }
}

function updateSenderProgress(bytes, total) {
  const percent = Math.min(100, Math.round((bytes / total) * 100));
  $('sender-progress-bar').style.width = `${percent}%`;
  $('sender-percent-text').innerText = `${percent}%`;
  $('sender-bytes-text').innerText = `${(bytes / (1024 * 1024)).toFixed(2)} MB / ${(total / (1024 * 1024)).toFixed(2)} MB`;
  $('sender-speed-text').innerText = calculateSpeed(bytes) + ' MB/s';
}

function updateReceiverProgress(bytes, total) {
  const percent = Math.min(100, Math.round((bytes / total) * 100));
  $('receiver-progress-bar').style.width = `${percent}%`;
  $('receiver-percent-text').innerText = `${percent}%`;
  $('receiver-bytes-text').innerText = `${(bytes / (1024 * 1024)).toFixed(2)} MB / ${(total / (1024 * 1024)).toFixed(2)} MB`;
  $('receiver-speed-text').innerText = calculateSpeed(bytes) + ' MB/s';
}

function calculateSpeed(bytes) {
  const now = Date.now();
  const elapsed = (now - state.lastSpeedTime) / 1000;
  if (elapsed >= 1) {
    const deltaBytes = bytes - state.lastSpeedBytes;
    state.currentSpeed = deltaBytes / elapsed / (1024 * 1024);
    state.lastSpeedTime = now;
    state.lastSpeedBytes = bytes;
  }
  return state.currentSpeed.toFixed(2);
}

async function downloadReceivedFile() {
  if (!state.receivedBuffer || !state.receivedFileInfo) return;

  try {
    // Validate received data
    if (state.receivedBuffer.byteLength === 0) {
      showToast('No file data to download', 'error');
      return;
    }

    // Create blob from received data with proper MIME type
    const mimeType = state.receivedFileInfo.name.split('.').pop() || 'application/octet-stream';
    const blob = new Blob([state.receivedBuffer], { type: mimeType });
    const url = URL.createObjectURL(blob);

    // Small delay to ensure blob is fully created (fixes Safari WebKit error)
    await new Promise(resolve => setTimeout(resolve, 100));

    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || 
                  (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

    if (isIOS) {
      // iOS Safari: open in new tab and let user long-press to save
      const newWindow = window.open(url, '_blank');
      if (newWindow) {
        showToast('📱 Long-press the file and select "Download" to save it', 'info');
      } else {
        showToast('Popup blocked. Please allow popups for this site.', 'error');
      }
    } else {
      // Desktop/Android: create hidden link and click it
      const a = document.createElement('a');
      a.href = url;
      a.download = state.receivedFileInfo.name;
      a.style.display = 'none';
      document.body.appendChild(a);
      
      // Trigger download
      a.click();
      
      // Cleanup after a short delay
      setTimeout(() => {
        if (a.parentNode) {
          document.body.removeChild(a);
        }
        URL.revokeObjectURL(url);
      }, 1000);
    }

    // For non-iOS, also revoke the URL after longer delay
    if (!isIOS) {
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    }
  } catch (err) {
    console.error('Download error:', err);
    showToast('Download failed. Try long-pressing the file to save it.', 'error');
  }
}

// ============================================================
// 8. Cleanup & Reset
// ============================================================
function resetTransferState() {
  // Stop QR animation
  if (state.animatedInterval) {
    clearInterval(state.animatedInterval);
    state.animatedInterval = null;
  }

  // Close data channel
  if (state.dc) {
    try { state.dc.close(); } catch {}
    state.dc = null;
  }

  // Close peer connection
  if (state.pc) {
    try { state.pc.close(); } catch {}
    state.pc = null;
  }

  // Close WebSocket (disables auto-reconnect)
  if (state.ws) {
    state.ws.onopen = state.ws.onmessage = state.ws.onerror = state.ws.onclose = null;
    try { state.ws.close(); } catch {}
    state.ws = null;
  }

  stopCamera();

  state.role = null;
  state.roomId = null;
  state.localKeyPair = null;
  state.sharedAesKey = null;
  state.selectedFile = null;
  state.transferring = false;
  state.receivedChunks = [];
  state.receivedFileInfo = null;
  state.receivedBuffer = null;
  state.transferredBytes = 0;
  state.pendingCandidates = [];
  state.qrFrames = null;

  // Hide QR overlay
  const overlay = $('qr-connected-overlay');
  if (overlay) overlay.classList.add('hidden');

  updateSignalBadge('offline');
}

// ============================================================
// 9. UI Navigation & Tabs
// ============================================================
function switchTab(tab) {
  // Stop everything when switching
  resetTransferState();

  state.role = tab;
  $('tab-send').classList.toggle('active', tab === 'send');
  $('tab-receive').classList.toggle('active', tab === 'receive');
  $('panel-send').classList.toggle('hidden', tab !== 'send');
  $('panel-receive').classList.toggle('hidden', tab !== 'receive');

  // Reset UI
  if (tab === 'send') {
    $('receiver-peer-status').innerText = 'Idle';
    $('sender-progress-card').classList.add('hidden');
    $('receiver-progress-card').classList.add('hidden');
    $('download-box').classList.add('hidden');
    $('qr-placeholder').classList.remove('hidden');
    $('qr-canvas').classList.add('hidden');
    $('qr-info').classList.add('hidden');
    $('qr-connected-overlay').classList.add('hidden');
    $('sender-connection-note').classList.add('hidden');
    resetSteps('send');
    updateSendButtonState();
  } else {
    $('receiver-peer-status').innerText = 'Idle';
    $('scanner-placeholder').classList.remove('hidden');
    $('scanner-placeholder').innerHTML = '<div class="placeholder-icon">📷</div><p>Start camera to scan the pairing QR</p>';
    $('scan-progress-bar').style.width = '0%';
    $('scan-progress-text').innerText = 'Scan Progress: 0%';
    $('receiver-progress-card').classList.add('hidden');
    $('download-box').classList.add('hidden');
    $('recv-connection-note').classList.add('hidden');
    resetSteps('recv');
  }
}

// Clean up on page unload
window.addEventListener('beforeunload', () => {
  resetTransferState();
});