// Minimal VLESS-over-WebSocket relay on a plain Node HTTP server.
// No dependencies. Listens on process.env.PORT, binds 0.0.0.0.
// UUID comes from the UUID environment variable (never hardcoded).
const http = require('http');
const net = require('net');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '3000', 10);
const UUID_HEX = (process.env.UUID || '').replace(/-/g, '').toLowerCase();
const WS_PATH = process.env.WS_PATH || '/ws';
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const server = http.createServer((req, res) => {
  if (req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<!doctype html><html><head><title>abasthan-node</title></head>' +
    '<body><h1>abasthan-node</h1><p>A small web service.</p></body></html>');
});

function wsAccept(key) {
  return crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
}

function encodeFrame(payload) {
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x82, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x82; header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x82; header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

// Incremental WebSocket frame parser. Calls onMessage(fullPayload) for each
// complete data message, handles ping/close internally via callbacks.
function makeParser(onMessage, onPongNeeded, onClose) {
  let buf = Buffer.alloc(0);
  let fragments = [];
  let fragmenting = false;
  return function push(chunk) {
    buf = Buffer.concat([buf, chunk]);
    while (true) {
      if (buf.length < 2) return;
      const b0 = buf[0], b1 = buf[1];
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < off + 2) return;
        len = buf.readUInt16BE(off); off += 2;
      } else if (len === 127) {
        if (buf.length < off + 8) return;
        len = Number(buf.readBigUInt64BE(off)); off += 8;
      }
      let maskKey = null;
      if (masked) {
        if (buf.length < off + 4) return;
        maskKey = buf.subarray(off, off + 4); off += 4;
      }
      if (buf.length < off + len) return;
      let payload = buf.subarray(off, off + len);
      buf = buf.subarray(off + len);
      if (masked) {
        const un = Buffer.alloc(len);
        for (let i = 0; i < len; i++) un[i] = payload[i] ^ maskKey[i % 4];
        payload = un;
      } else {
        payload = Buffer.from(payload);
      }
      if (opcode === 0x8) { onClose(); return; }
      if (opcode === 0x9) { onPongNeeded(payload); continue; }
      if (opcode === 0xA) continue;
      if (opcode === 0x0 || opcode === 0x1 || opcode === 0x2) {
        if (!fin) {
          if (opcode !== 0x0) { fragmenting = true; fragments = [payload]; }
          else if (fragmenting) fragments.push(payload);
          continue;
        }
        if (opcode === 0x0 && fragmenting) {
          fragments.push(payload);
          payload = Buffer.concat(fragments);
          fragmenting = false; fragments = [];
        }
        onMessage(payload);
      }
    }
  };
}

server.on('upgrade', (req, socket, head) => {
  const url = (req.url || '').split('?')[0];
  if (url !== WS_PATH || !UUID_HEX) { socket.destroy(); return; }
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n');
  if (head && head.length) socket.unshift(head);

  let target = null;
  let established = false;
  let pendingWrites = [];
  let closed = false;

  function cleanup() {
    if (closed) return;
    closed = true;
    try { socket.destroy(); } catch (e) {}
    if (target) { try { target.destroy(); } catch (e) {} }
  }

  function sendFrame(payload) {
    if (closed) return;
    try { socket.write(encodeFrame(payload)); } catch (e) { cleanup(); }
  }

  const push = makeParser((msg) => {
    if (!established) {
      // Parse VLESS request header.
      try {
        if (msg.length < 24) { cleanup(); return; }
        const version = msg[0];
        if (msg.subarray(1, 17).toString('hex') !== UUID_HEX) { cleanup(); return; }
        let off = 17;
        const addonLen = msg[off]; off += 1 + addonLen;
        const command = msg[off]; off += 1;
        if (command !== 1) { cleanup(); return; } // TCP only
        const port = msg.readUInt16BE(off); off += 2;
        const addrType = msg[off]; off += 1;
        let host;
        if (addrType === 1) {
          host = Array.from(msg.subarray(off, off + 4)).join('.'); off += 4;
        } else if (addrType === 2) {
          const dlen = msg[off]; off += 1;
          host = msg.subarray(off, off + dlen).toString('utf8'); off += dlen;
        } else if (addrType === 3) {
          const parts = [];
          for (let i = 0; i < 16; i += 2) parts.push(msg.readUInt16BE(off + i).toString(16));
          host = parts.join(':'); off += 16;
        } else { cleanup(); return; }
        const initial = msg.subarray(off);
        established = true;
        target = net.connect(port, host);
        target.on('connect', () => {
          // VLESS response header: [version, 0x00]
          sendFrame(Buffer.from([version, 0]));
          if (initial.length) target.write(initial);
          for (const p of pendingWrites) target.write(p);
          pendingWrites = [];
        });
        target.on('data', (d) => sendFrame(d));
        target.on('error', cleanup);
        target.on('close', cleanup);
      } catch (e) { cleanup(); }
    } else if (target && target.writable) {
      if (target.readyState === 'open') target.write(msg);
      else pendingWrites.push(msg);
    }
  }, (payload) => {
    // ping -> pong (control frame, opcode 0xA)
    if (closed) return;
    const len = payload.length;
    const header = Buffer.from([0x8a, len]);
    try { socket.write(Buffer.concat([header, payload])); } catch (e) { cleanup(); }
  }, cleanup);

  socket.on('data', push);
  socket.on('error', cleanup);
  socket.on('close', cleanup);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('listening on ' + PORT);
});
