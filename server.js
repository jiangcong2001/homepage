const express = require('express');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 8000;
const DATA_FILE = path.join(__dirname, 'data.json');
const JWT_SECRET = process.env.JWT_SECRET || 'homepage-secret-key-' + Date.now();

app.use(express.json());
app.use(cookieParser());
app.use(express.static(__dirname));

function readData() {
  const raw = fs.readFileSync(DATA_FILE, 'utf-8');
  return JSON.parse(raw);
}

function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

function authMiddleware(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: '未登录' });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: '登录已过期' });
  }
}

app.get('/api/content', (req, res) => {
  const data = readData();
  const { admin, ...content } = data;
  res.json(content);
});

app.put('/api/content', authMiddleware, (req, res) => {
  const data = readData();
  const { site, profile, sidebar, social, sites, projects, footer } = req.body;
  if (site) data.site = site;
  if (profile) data.profile = profile;
  if (sidebar) data.sidebar = sidebar;
  if (social) data.social = social;
  if (sites) data.sites = sites;
  if (projects) data.projects = projects;
  if (footer) data.footer = footer;
  writeData(data);
  res.json({ success: true });
});

app.post('/api/login', (req, res) => {
  const { password } = req.body;
  const data = readData();
  if (password === data.admin.password) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, { httpOnly: true, maxAge: 86400000, sameSite: 'strict' });
    res.json({ success: true });
  } else {
    res.status(401).json({ error: '密码错误' });
  }
});

app.post('/api/change-password', authMiddleware, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: '密码至少6位' });
  }
  const data = readData();
  data.admin.password = newPassword;
  writeData(data);
  res.json({ success: true });
});

app.get('/api/check-auth', authMiddleware, (req, res) => {
  res.json({ authenticated: true });
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://0.0.0.0:${PORT}`);
  console.log(`Admin panel: http://0.0.0.0:${PORT}/admin`);
});
