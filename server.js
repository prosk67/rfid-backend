const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const DATA_DIR = path.join(__dirname, 'data');
const LOG_DIR = path.join(__dirname, 'logs');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PENDING_AUTH_FILE = path.join(DATA_DIR, 'pending_auth.json');
const ADMIN_FILE = path.join(DATA_DIR, 'admin.json');
const ACCESS_LOG = path.join(LOG_DIR, 'access.log');
const INTRUSION_LOG = path.join(LOG_DIR, 'intrusion.log');

// --- setup ---
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([], null, 2));
if (!fs.existsSync(PENDING_AUTH_FILE)) fs.writeFileSync(PENDING_AUTH_FILE, JSON.stringify([], null, 2));
if (!fs.existsSync(ADMIN_FILE)) {
  const defaultHash = crypto.createHash('sha256').update('admin').digest('hex');
  fs.writeFileSync(ADMIN_FILE, JSON.stringify([{ username: 'admin', password: defaultHash }], null, 2));
}

app.use(express.static('public'));

// Root -> login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// --- auth helpers ---
const sessions = new Map(); // token -> { username, expiresAt }

function readAdmins() {
  try {
    return JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
  } catch (e) {
    return [];
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  header.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx > -1) cookies[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return cookies;
}

function getToken(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) return auth.slice(7);
  return parseCookies(req).token || req.query.token;
}

function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username, expiresAt: Date.now() + 24 * 60 * 60 * 1000 }); // 24h
  return token;
}

function destroySession(token) {
  sessions.delete(token);
}

function authRequired(req, res, next) {
  const token = getToken(req);
  const session = token && sessions.get(token);
  if (!session) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return res.status(401).json({ error: 'unauthorized' });
  }
  req.session = session;
  next();
}

function setAuthCookie(res, token) {
  res.setHeader('Set-Cookie', `token=${token}; Path=/; HttpOnly; Max-Age=86400; SameSite=Lax`);
}

app.get('/admin', (req, res) => {
  const token = getToken(req);
  const session = token && sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// --- auth routes ---
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  const admins = readAdmins();
  const hash = crypto.createHash('sha256').update(String(password)).digest('hex');
  const admin = admins.find(a => a.username === username && a.password === hash);

  if (!admin) return res.status(401).json({ error: 'invalid credentials' });

  const token = createSession(admin.username);
  setAuthCookie(res, token);
  res.json({ ok: true, token, username: admin.username });
});

app.post('/api/logout', (req, res) => {
  const token = getToken(req);
  if (token) destroySession(token);
  res.setHeader('Set-Cookie', 'token=; Path=/; HttpOnly; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', authRequired, (req, res) => {
  res.json({ username: req.session.username });
});

// --- helpers ---
function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (e) {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function readPendingAuth() {
  try {
    return JSON.parse(fs.readFileSync(PENDING_AUTH_FILE, 'utf8'));
  } catch (e) {
    return [];
  }
}

function writePendingAuth(requests) {
  fs.writeFileSync(PENDING_AUTH_FILE, JSON.stringify(requests, null, 2));
}

function appendLog(filePath, entry) {
  const line = JSON.stringify({ ...entry, timestamp: new Date().toISOString() }) + '\n';
  fs.appendFileSync(filePath, line);
}

// --- SSE / real-time ---
const sseClients = new Set();

function broadcast(channel, payload) {
  const data = JSON.stringify({ channel, payload });
  for (const client of sseClients) {
    try {
      client.res.write(`event: ${channel}\ndata: ${data}\n\n`);
    } catch (e) {
      sseClients.delete(client);
    }
  }
}

// --- routes ---

// STM sends scanned UID -> check against users.json, log result
app.post('/api/auth', (req, res) => {
  const { uid } = req.body;
  if (!uid) return res.status(400).json({ error: 'uid required' });

  const users = readUsers();
  const user = users.find(u => u.uid === uid);

  // Grant access only if user exists and auth_status is "Granted"
  if (user && user.auth_status === 'Granted') {
    const status = 'granted';
    appendLog(ACCESS_LOG, { uid, status, name: user.name });
    broadcast('access', { uid, status, name: user.name, granted: true });
    return res.json({ granted: true, name: user.name, auth_status: 'Granted' });
  }

  // Otherwise (denied or non-existent) -> queue for admin approval
  const pending = readPendingAuth();
  if (!pending.some(p => p.uid === uid)) {
    pending.push({ uid, name: '', status: 'pending', created_at: new Date().toISOString() });
    writePendingAuth(pending);
  }

  const status = 'denied';
  appendLog(ACCESS_LOG, { uid, status, name: user ? user.name : null });
  broadcast('access', { uid, status, name: user ? user.name : null, granted: false });
  broadcast('pending', { action: 'add', uid });
  res.json({ granted: false, name: user ? user.name : null, auth_status: 'denied' });
});

// List pending auth requests
app.get('/api/auth/pending', authRequired, (req, res) => {
  res.json(readPendingAuth());
});

// Admin approves a pending auth request
app.post('/api/auth/approve/:uid', authRequired, (req, res) => {
  const { uid } = req.params;
  const { name } = req.body;

  const pending = readPendingAuth();
  const idx = pending.findIndex(p => p.uid === uid);
  if (idx === -1) {
    return res.status(404).json({ error: 'uid not pending approval' });
  }

  // Check if user already exists
  const users = readUsers();
  if (!users.some(u => u.uid === uid)) {
    users.push({ uid, name: name || pending[idx].name || null, active: true, auth_status: 'Granted', created_at: new Date().toISOString() });
    writeUsers(users);
  } else {
    // Update existing user's status
    const user = users.find(u => u.uid === uid);
    user.active = true;
    user.name = name || user.name;
    user.auth_status = 'Granted';
    writeUsers(users);
  }

  // Remove from pending queue
  pending.splice(idx, 1);
  writePendingAuth(pending);

  broadcast('pending', { action: 'remove', uid });
  broadcast('users', { action: 'approve', uid });
  res.json({ ok: true, auth_status: 'Granted' });
});

// Update name of a pending auth request
app.post('/api/auth/pending/name/:uid', authRequired, (req, res) => {
  const { uid } = req.params;
  const { name } = req.body;
  if (name === undefined) return res.status(400).json({ error: 'name required' });

  const pending = readPendingAuth();
  const idx = pending.findIndex(p => p.uid === uid);
  if (idx === -1) {
    return res.status(404).json({ error: 'uid not pending approval' });
  }

  pending[idx].name = name;
  writePendingAuth(pending);

  broadcast('pending', { action: 'name', uid });
  res.json({ ok: true });
});

// Admin rejects a pending auth request
app.post('/api/auth/reject/:uid', authRequired, (req, res) => {
  const { uid } = req.params;

  const pending = readPendingAuth();
  const idx = pending.findIndex(p => p.uid === uid);
  if (idx === -1) {
    return res.status(404).json({ error: 'uid not pending approval' });
  }

  pending.splice(idx, 1);
  writePendingAuth(pending);

  broadcast('pending', { action: 'remove', uid });
  res.json({ ok: true, auth_status: 'denied' });
});

// Admin enrolls new RFID from STM keypad/OLED flow
app.post('/api/users', authRequired, (req, res) => {
  const { uid, name } = req.body;
  if (!uid) return res.status(400).json({ error: 'uid required' });

  const users = readUsers();
  if (users.some(u => u.uid === uid)) {
    return res.status(409).json({ error: 'uid already exists' });
  }

  const auth_status = 'Granted';
  users.push({ uid, name: name || null, active: true, auth_status, created_at: new Date().toISOString() });
  writeUsers(users);

  broadcast('users', { action: 'add', uid });
  res.json({ ok: true });
});

// List users
app.get('/api/users', authRequired, (req, res) => {
  res.json(readUsers());
});

// Remove a user
app.delete('/api/users/:uid', authRequired, (req, res) => {
  const users = readUsers();
  const filtered = users.filter(u => u.uid !== req.params.uid);
  if (filtered.length === users.length) {
    return res.status(404).json({ error: 'uid not found' });
  }
  writeUsers(filtered);
  broadcast('users', { action: 'remove', uid: req.params.uid });
  res.json({ ok: true });
});

// Vibration / magnetic switch break-in events
app.post('/api/intrusion', (req, res) => {
  const { sensor } = req.body;
  if (!sensor) return res.status(400).json({ error: 'sensor required' });

  appendLog(INTRUSION_LOG, { sensor });
  broadcast('intrusion', { sensor });
  res.json({ ok: true });
});

// Read access log (last N lines, default 50)
app.get('/api/logs/access', authRequired, (req, res) => {
  res.json(readLogFile(ACCESS_LOG, req.query.limit));
});

// Read all logs in format: uid | authorization status | timestamp
app.get('/api/logs', authRequired, (req, res) => {
  const logs = readLogFile(ACCESS_LOG, req.query.limit);
  res.json(logs.map(l => ({
    uid: l.uid,
    status: l.status,
    timestamp: l.timestamp
  })));
});

// Create new access log entry
app.post('/api/logs', authRequired, (req, res) => {
  const { uid, status } = req.body;
  if (!uid || !status) return res.status(400).json({ error: 'uid and status required' });

  appendLog(ACCESS_LOG, { uid, status, name: null });
  broadcast('access', { uid, status, name: null, granted: status === 'granted' });
  res.json({ ok: true });
});

// Read intrusion log (last N lines, default 50)
app.get('/api/logs/intrusion', authRequired, (req, res) => {
  res.json(readLogFile(INTRUSION_LOG, req.query.limit));
});

// Server-Sent Events stream for real-time updates
app.get('/api/events', authRequired, (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });
  res.flushHeaders();

  const client = { res };
  sseClients.add(client);

  // Send a hello message to confirm connection
  res.write('event: hello\ndata: {"channel":"hello"}\n\n');

  req.on('close', () => {
    sseClients.delete(client);
  });
});

function readLogFile(filePath, limit) {
  if (!fs.existsSync(filePath)) return [];
  const lines = fs.readFileSync(filePath, 'utf8').trim().split('\n').filter(Boolean);
  const n = parseInt(limit) || 50;
  return lines.slice(-n).map(l => JSON.parse(l)).reverse();
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`RFID doorlock server running on port ${PORT}`);
});
