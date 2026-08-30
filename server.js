const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const DATA_DIR = path.join(__dirname, 'data');
const LOG_DIR = path.join(__dirname, 'logs');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ACCESS_LOG = path.join(LOG_DIR, 'access.log');
const INTRUSION_LOG = path.join(LOG_DIR, 'intrusion.log');

// --- setup ---
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([], null, 2));

app.use(express.static('public'));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
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

function appendLog(filePath, entry) {
  const line = JSON.stringify({ ...entry, timestamp: new Date().toISOString() }) + '\n';
  fs.appendFileSync(filePath, line);
}

// --- routes ---

// STM sends scanned UID -> check against users.json, log result
app.post('/api/auth', (req, res) => {
  const { uid } = req.body;
  if (!uid) return res.status(400).json({ error: 'uid required' });

  const users = readUsers();
  const user = users.find(u => u.uid === uid && u.active !== false);

  const status = user ? 'granted' : 'denied';
  appendLog(ACCESS_LOG, { uid, status, name: user ? user.name : null });

  res.json({ granted: !!user, name: user ? user.name : null });
});

// Admin enrolls new RFID from STM keypad/OLED flow
app.post('/api/users', (req, res) => {
  const { uid, name } = req.body;
  if (!uid) return res.status(400).json({ error: 'uid required' });

  const users = readUsers();
  if (users.some(u => u.uid === uid)) {
    return res.status(409).json({ error: 'uid already exists' });
  }

  users.push({ uid, name: name || null, active: true, created_at: new Date().toISOString() });
  writeUsers(users);

  res.json({ ok: true });
});

// List users
app.get('/api/users', (req, res) => {
  res.json(readUsers());
});

// Remove a user
app.delete('/api/users/:uid', (req, res) => {
  const users = readUsers();
  const filtered = users.filter(u => u.uid !== req.params.uid);
  if (filtered.length === users.length) {
    return res.status(404).json({ error: 'uid not found' });
  }
  writeUsers(filtered);
  res.json({ ok: true });
});

// Vibration / magnetic switch break-in events
app.post('/api/intrusion', (req, res) => {
  const { sensor } = req.body;
  if (!sensor) return res.status(400).json({ error: 'sensor required' });

  appendLog(INTRUSION_LOG, { sensor });
  res.json({ ok: true });
});

// Read access log (last N lines, default 50)
app.get('/api/logs/access', (req, res) => {
  res.json(readLogFile(ACCESS_LOG, req.query.limit));
});

// Read intrusion log (last N lines, default 50)
app.get('/api/logs/intrusion', (req, res) => {
  res.json(readLogFile(INTRUSION_LOG, req.query.limit));
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
