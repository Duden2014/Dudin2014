require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const cors = require('cors');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// Ensure DB file exists (useful when mounted from host)
const DB_FILE = process.env.DB_FILE || 'data.db';
if (!fs.existsSync(DB_FILE)) {
  fs.closeSync(fs.openSync(DB_FILE, 'w'));
}

const db = new Database(DB_FILE);

// Create tables if not exist
db.exec(`
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin INTEGER DEFAULT 0,
  is_pro INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  to_user_id INTEGER, -- NULL => broadcast to all
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (to_user_id) REFERENCES users(id) ON DELETE SET NULL
);
`);

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const DAILY_LIMIT = 10;

// Serve static frontend
app.use(express.static('public'));

// Helpers
function createToken(user) {
  return jwt.sign({ id: user.id, username: user.username, is_admin: !!user.is_admin, is_pro: !!user.is_pro }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Routes

// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  const exists = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const isFirstUserAdmin = (exists === 0); // first registered becomes admin
  const password_hash = await bcrypt.hash(password, 10);

  try {
    const info = db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)').run(username, password_hash, isFirstUserAdmin ? 1 : 0);
    const user = db.prepare('SELECT id, username, is_admin, is_pro FROM users WHERE id = ?').get(info.lastInsertRowid);
    const token = createToken(user);
    return res.json({ user, token, message: isFirstUserAdmin ? 'First user — admin' : undefined });
  } catch (e) {
    return res.status(400).json({ error: 'username already exists' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT id, username, password_hash, is_admin, is_pro FROM users WHERE username = ?').get(username);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  const publicUser = { id: user.id, username: user.username, is_admin: !!user.is_admin, is_pro: !!user.is_pro };
  const token = createToken(publicUser);
  return res.json({ user: publicUser, token });
});

// Create post (direct message or broadcast)
// body: { content, toUserId }  (toUserId optional — omit or null => broadcast)
app.post('/post', authMiddleware, (req, res) => {
  const { content, toUserId } = req.body;
  if (!content || content.trim().length === 0) return res.status(400).json({ error: 'content required' });

  const user = db.prepare('SELECT id, is_pro FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(400).json({ error: 'User not found' });

  if (!user.is_pro) {
    // count posts today
    const count = db.prepare(
      `SELECT COUNT(*) as c FROM posts
       WHERE author_id = ? AND date(created_at) = date('now','localtime')`
    ).get(user.id).c;
    if (count >= DAILY_LIMIT) return res.status(403).json({ error: `Daily limit reached (${DAILY_LIMIT}). Ask admin to grant Pro.` });
  }

  // If toUserId is provided, check user exists
  let toUserIdVal = null;
  if (toUserId !== undefined && toUserId !== null) {
    const u = db.prepare('SELECT id FROM users WHERE id = ?').get(toUserId);
    if (!u) return res.status(400).json({ error: 'Recipient user not found' });
    toUserIdVal = toUserId;
  }

  const info = db.prepare('INSERT INTO posts (author_id, content, to_user_id) VALUES (?, ?, ?)').run(user.id, content.trim(), toUserIdVal);
  const post = db.prepare('SELECT p.id, p.content, p.to_user_id, p.created_at, u.username as author FROM posts p JOIN users u ON p.author_id = u.id WHERE p.id = ?').get(info.lastInsertRowid);

  return res.json({ post });
});

// Get posts
// ?inbox=true => messages addressed to me OR broadcast
// ?authorId=... => posts by author
// ?toUserId=... => posts sent to a specific user (including broadcasts if to_user_id is NULL)
app.get('/posts', authMiddleware, (req, res) => {
  const { inbox, authorId, toUserId } = req.query;
  let rows;
  if (inbox === 'true') {
    // messages to me OR broadcast (to_user_id IS NULL)
    rows = db.prepare(
      `SELECT p.id, p.content, p.to_user_id, p.created_at, u.username as author
       FROM posts p JOIN users u ON p.author_id = u.id
       WHERE (p.to_user_id IS NULL) OR (p.to_user_id = ?)
       ORDER BY p.created_at DESC
       LIMIT 200`
    ).all(req.user.id);
  } else if (authorId) {
    rows = db.prepare(
      `SELECT p.id, p.content, p.to_user_id, p.created_at, u.username as author
       FROM posts p JOIN users u ON p.author_id = u.id
       WHERE p.author_id = ?
       ORDER BY p.created_at DESC
       LIMIT 200`
    ).all(authorId);
  } else if (toUserId) {
    rows = db.prepare(
      `SELECT p.id, p.content, p.to_user_id, p.created_at, u.username as author
       FROM posts p JOIN users u ON p.author_id = u.id
       WHERE p.to_user_id = ? OR p.to_user_id IS NULL
       ORDER BY p.created_at DESC
       LIMIT 200`
    ).all(toUserId);
  } else {
    // recent broadcasts and public posts
    rows = db.prepare(
      `SELECT p.id, p.content, p.to_user_id, p.created_at, u.username as author
       FROM posts p JOIN users u ON p.author_id = u.id
       ORDER BY p.created_at DESC
       LIMIT 200`
    ).all();
  }
  return res.json({ posts: rows });
});

// Admin: grant Pro to user
app.post('/admin/grant-pro', authMiddleware, (req, res) => {
  const { userId } = req.body;
  if (!req.user.is_admin) return res.status(403).json({ error: 'Admin only' });
  if (!userId) return res.status(400).json({ error: 'userId required' });
  const user = db.prepare('SELECT id, username, is_pro FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(400).json({ error: 'User not found' });
  db.prepare('UPDATE users SET is_pro = 1 WHERE id = ?').run(userId);
  return res.json({ message: `User ${user.username} is now Pro` });
});

// Admin: revoke Pro
app.post('/admin/revoke-pro', authMiddleware, (req, res) => {
  const { userId } = req.body;
  if (!req.user.is_admin) return res.status(403).json({ error: 'Admin only' });
  if (!userId) return res.status(400).json({ error: 'userId required' });
  const user = db.prepare('SELECT id, username, is_pro FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(400).json({ error: 'User not found' });
  db.prepare('UPDATE users SET is_pro = 0 WHERE id = ?').run(userId);
  return res.json({ message: `Pro revoked for ${user.username}` });
});

// Get current user info
app.get('/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, username, is_admin, is_pro FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  return res.json({ user });
});

// List users (admin only)
app.get('/admin/users', authMiddleware, (req, res) => {
  if (!req.user.is_admin) return res.status(403).json({ error: 'Admin only' });
  const users = db.prepare('SELECT id, username, is_admin, is_pro, created_at FROM users ORDER BY id').all();
  return res.json({ users });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Server running on port', PORT);
});
