const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 4000;
const CLIENT_DIR = path.join(__dirname, '..', 'client');

// MIME types for static file serving
const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.map': 'application/json',
};

// HTTP Server - serves static client files AND health check
const server = http.createServer((req, res) => {
  // Health check endpoint
  if (req.url === '/api/health') {
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok', service: 'FluxDrop 2.0 Signaling Server' }));
    return;
  }

  // Serve static files from client directory
  // / serves home.html (landing page), /app serves index.html (the app)
  let requestUrl = req.url;
  if (requestUrl === '/' || requestUrl === '/home') {
    requestUrl = '/home.html';
  } else if (requestUrl === '/app' || requestUrl === '/app/') {
    requestUrl = '/index.html';
  }
  let filePath = path.join(CLIENT_DIR, requestUrl);
  
  // Prevent path traversal
  if (!filePath.startsWith(CLIENT_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(filePath, (err, content) => {
    if (err) {
      // If file not found, try index.html (SPA fallback)
      if (err.code === 'ENOENT' && !path.extname(filePath)) {
        filePath = path.join(CLIENT_DIR, 'index.html');
        fs.readFile(filePath, (err2, content2) => {
          if (err2) {
            res.writeHead(404);
            res.end('Not Found');
            return;
          }
          res.setHeader('Content-Type', 'text/html');
          res.writeHead(200);
          res.end(content2);
        });
        return;
      }
      res.writeHead(404);
      res.end('Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'no-cache');
    res.writeHead(200);
    res.end(content);
  });
});

// WebSocket Server attached to HTTP server matching /signal-ws path
const wss = new WebSocketServer({ server, path: '/signal-ws' });

// Room state storage: roomId -> { sender: WebSocket, receiver: WebSocket }
const rooms = new Map();

// Heartbeat interval to detect dead connections
const HEARTBEAT_INTERVAL = 30000; // 30 seconds

function heartbeat() {
  this.isAlive = true;
}

wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  ws.on('pong', heartbeat);

  let currentRoomId = null;
  let currentRole = null;

  console.log(`[WS] New connection from ${req.socket.remoteAddress}`);

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      const { type, roomId, role, payload } = data;

      if (type === 'join') {
        // Validate roomId and role
        if (!roomId || typeof roomId !== 'string' || roomId.length > 64) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid roomId' }));
          return;
        }
        if (role !== 'sender' && role !== 'receiver') {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid role' }));
          return;
        }

        // If already in a room, leave it first
        if (currentRoomId && currentRoomId !== roomId && rooms.has(currentRoomId)) {
          const oldRoom = rooms.get(currentRoomId);
          if (currentRole === 'sender') oldRoom.sender = null;
          if (currentRole === 'receiver') oldRoom.receiver = null;
          if (!oldRoom.sender && !oldRoom.receiver) rooms.delete(currentRoomId);
        }

        currentRoomId = roomId;
        currentRole = role;

        let room = rooms.get(roomId);
        if (!room) {
          room = { sender: null, receiver: null };
          rooms.set(roomId, room);
        }

        // If same role already exists in room, replace it
        if (role === 'sender' && room.sender && room.sender !== ws) {
          room.sender.close(4000, 'Replaced by new sender');
        }
        if (role === 'receiver' && room.receiver && room.receiver !== ws) {
          room.receiver.close(4000, 'Replaced by new receiver');
        }

        if (role === 'sender') room.sender = ws;
        if (role === 'receiver') room.receiver = ws;

        console.log(`[ROOM ${roomId}] ${role} joined`);

        // Notify client that join succeeded
        ws.send(JSON.stringify({
          type: 'joined',
          roomId,
          role,
          peerPresent: !!(role === 'sender' ? room.receiver : room.sender)
        }));

        // Notify existing peer if connected
        const peer = role === 'sender' ? room.receiver : room.sender;
        if (peer && peer !== ws && peer.readyState === 1) { // 1 = OPEN
          peer.send(JSON.stringify({ type: 'peer-joined', role }));
        }
        return;
      }

      if (!currentRoomId || !rooms.has(currentRoomId)) return;

      const room = rooms.get(currentRoomId);
      const targetPeer = currentRole === 'sender' ? room.receiver : room.sender;

      // Relay WebRTC signaling messages (offer, answer, ice-candidate)
      if (targetPeer && targetPeer !== ws && targetPeer.readyState === 1) {
        targetPeer.send(JSON.stringify({ type, senderRole: currentRole, payload }));
      }
    } catch (err) {
      console.error('Message handling error:', err);
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
    }
  });

  ws.on('close', (code, reason) => {
    if (currentRoomId && rooms.has(currentRoomId)) {
      const room = rooms.get(currentRoomId);
      const peer = currentRole === 'sender' ? room.receiver : room.sender;
      if (peer && peer !== ws && peer.readyState === 1) {
        peer.send(JSON.stringify({ type: 'peer-disconnected' }));
      }
      if (currentRole === 'sender' && room.sender === ws) room.sender = null;
      if (currentRole === 'receiver' && room.receiver === ws) room.receiver = null;
      if (!room.sender && !room.receiver) {
        rooms.delete(currentRoomId);
      }
      console.log(`[ROOM ${currentRoomId}] ${currentRole} disconnected`);
    }
  });

  ws.on('error', (err) => {
    console.error(`[WS] Error: ${err.message}`);
  });
});

// Heartbeat check - terminate dead connections
const heartbeatTimer = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      ws.terminate();
      return;
    }
    ws.isAlive = false;
    ws.ping();
  });
}, HEARTBEAT_INTERVAL);

wss.on('close', () => {
  clearInterval(heartbeatTimer);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 FluxDrop 2.0 Server running on http://0.0.0.0:${PORT}`);
  console.log(`   - Static files: http://localhost:${PORT}/`);
  console.log(`   - WebSocket: ws://localhost:${PORT}/signal-ws`);
});