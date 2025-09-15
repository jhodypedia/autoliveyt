// app.js — FINAL
require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const layouts = require('express-ejs-layouts');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const { google } = require('googleapis');
const multer = require('multer');
const mkdirp = require('mkdirp');
const http = require('http');
const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const dayjs = require('dayjs');
const socketio = require('socket.io');
const cron = require('node-cron');
const db = require('./db');

const app = express();
const server = http.createServer(app);
const io = socketio(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const FFMPEG_PATH = process.env.FFMPEG_PATH || 'ffmpeg';
const SESSION_SECRET = process.env.SESSION_SECRET || 'session-secret';

// ===== Helpers =====
async function getSetting(keys) {
  const qmarks = keys.map(()=>'?').join(',');
  const [rows] = await db.execute(`SELECT key_name,value FROM settings WHERE key_name IN (${qmarks})`, keys);
  const m = {}; rows.forEach(r => m[r.key_name] = r.value); return m;
}
async function setSetting(pairs) {
  for (const [k, v] of Object.entries(pairs)) {
    await db.execute(
      'INSERT INTO settings (key_name,value) VALUES (?,?) ON DUPLICATE KEY UPDATE value=VALUES(value)',
      [k, v ?? '']
    );
  }
}
async function makeOAuthClientFromDB() {
  const cfg = await getSetting(['google_client_id','google_client_secret','google_redirect_uri']);
  return new google.auth.OAuth2(cfg.google_client_id, cfg.google_client_secret, cfg.google_redirect_uri);
}
const SCOPES = ['https://www.googleapis.com/auth/youtube'];

// ===== Express setup =====
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(layouts);
app.set('layout', 'layout');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));
mkdirp.sync(path.join(__dirname, 'uploads'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Session
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true }));

// Rate-limit auth endpoints
const authLimiter = rateLimit({ windowMs: 60_000, max: 30 });
app.use(['/login','/register'], authLimiter);

// Multer (video uploads + settings image upload)
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, path.join(__dirname,'uploads')),
  filename: (_, file, cb) => cb(null, `${Date.now()}_${file.originalname.replace(/\s+/g,'_')}`)
});
const upload = multer({ storage, limits: { fileSize: 6 * 1024**3 } }); // 6GB

// Socket.IO logs
const livePrc = new Map();   // jobId -> { pid }
const liveLogs = new Map();  // jobId -> [lines]
function pushLog(jobId, line) {
  const msg = `[${dayjs().format('HH:mm:ss')}] ${line}`;
  if (!liveLogs.has(jobId)) liveLogs.set(jobId, []);
  const arr = liveLogs.get(jobId); arr.push(msg); if (arr.length > 600) arr.shift();
  io.to(jobId).emit('log', msg);
}
io.on('connection', (socket) => { socket.on('join', (jobId) => socket.join(jobId)); });

// Locals
app.use(async (req, res, next) => {
  res.locals.BASE_URL = BASE_URL;
  res.locals.loggedIn = !!req.session.userId;
  res.locals.user = req.session.user || null;
  next();
});

// ===== Middlewares =====
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  if (req.session.user?.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}
async function requireSubscription(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  const [[u]] = await db.execute('SELECT subscription_expiry FROM users WHERE id=?', [req.session.userId]);
  if (!u?.subscription_expiry || new Date(u.subscription_expiry) < new Date()) {
    return res.status(403).send('⚠️ Subscription expired. Silakan perpanjang paket.');
  }
  next();
}

// ===== Auth Pages =====
app.get('/register', (req, res) => res.render('auth_register', { title: 'Register' }));
app.post('/register', async (req, res) => {
  try {
    const { email, password, name, paket } = req.body;
    if (!email || !password || !paket) return res.status(400).send('Lengkapi data');
    const [[dup]] = await db.execute('SELECT id FROM users WHERE email=?', [email]);
    if (dup) return res.status(400).send('Email sudah digunakan');

    const hash = await bcrypt.hash(password, 12);
    const [ins] = await db.execute(
      'INSERT INTO users (email, password_hash, name) VALUES (?,?,?)',
      [email.toLowerCase().trim(), hash, name || null]
    );
    const userId = ins.insertId;

    // Buat invoice payment (manual verify)
    const amount = paket === 'weekly' ? 30000 : (paket === 'monthly' ? 80000 : 0);
    if (!amount) return res.status(400).send('Paket tidak valid');

    const [[qPayload]] = await db.execute("SELECT value FROM settings WHERE key_name='qris_payload'");
    const [[qImage]] = await db.execute("SELECT value FROM settings WHERE key_name='qris_image'");
    const qris_payload = qPayload?.value || '';

    const [p] = await db.execute(
      'INSERT INTO payments (user_id,paket,amount,qris_payload) VALUES (?,?,?,?)',
      [userId, paket, amount, qris_payload]
    );

    // simpan user di session supaya invoice bisa tampil identitas
    req.session.userId = userId;
    req.session.user = { id: userId, email, role: 'user' };
    res.redirect('/invoice/' + p.insertId);
  } catch (e) {
    console.error(e); res.status(500).send('Register error');
  }
});

app.get('/invoice/:id', requireAuth, async (req, res) => {
  const [rows] = await db.execute(
    `SELECT p.*, u.email FROM payments p JOIN users u ON p.user_id=u.id WHERE p.id=? AND p.user_id=?`,
    [req.params.id, req.session.userId]
  );
  if (!rows.length) return res.status(404).send('Invoice tidak ditemukan');
  const payment = rows[0];
  const [srows] = await db.execute('SELECT key_name,value FROM settings WHERE key_name IN ("qris_payload","qris_image")');
  const settings = {}; srows.forEach(r=>settings[r.key_name]=r.value);
  res.render('status', { title: 'Invoice Pembayaran', job: null, payment, settings }); // pakai template sederhana (atau buat invoice.ejs terpisah)
});

app.get('/login', (req, res) => res.render('auth_login', { title: 'Login' }));
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [rows] = await db.execute('SELECT * FROM users WHERE email=?', [email.toLowerCase().trim()]);
    if (!rows.length) return res.status(400).send('Akun tidak ditemukan');
    const u = rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(400).send('Password salah');
    req.session.userId = u.id;
    req.session.user = { id: u.id, email: u.email, role: u.role };
    res.redirect('/');
  } catch (e) {
    console.error(e); res.status(500).send('Login error');
  }
});
app.get('/logout', (req, res) => { req.session.destroy(()=>res.redirect('/login')); });

// ===== Admin: verify payment manual, settings =====
app.get('/admin', requireAdmin, async (req, res) => {
  const [[u]] = await db.execute('SELECT COUNT(*) AS c FROM users'); 
  const [[a]] = await db.execute('SELECT COUNT(*) AS c FROM accounts'); 
  const [[active]] = await db.execute(`SELECT COUNT(*) AS c FROM jobs WHERE status='streaming'`);
  const [[sched]] = await db.execute(`SELECT COUNT(*) AS c FROM jobs WHERE status='scheduled'`);
  const [jobs] = await db.execute(
    `SELECT j.*, u.email AS user_email FROM jobs j JOIN users u ON j.user_id=u.id ORDER BY j.created_at DESC LIMIT 50`
  );
  const metrics = { total_users: u.c, total_accounts: a.c, active_jobs: active.c, scheduled_jobs: sched.c };
  res.render('admin_dashboard', { title: 'Admin Dashboard', metrics, jobs });
});

app.get('/admin/settings', requireAdmin, async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM settings');
  const settings = {}; rows.forEach(r=>settings[r.key_name]=r.value);
  res.render('admin_settings', { title: 'Pengaturan', settings });
});

const uploadQris = upload.fields([{ name: 'qris_image', maxCount: 1 }]);
app.post('/admin/settings', requireAdmin, uploadQris, async (req, res) => {
  try {
    const payload = {
      google_client_id: req.body.google_client_id || '',
      google_client_secret: req.body.google_client_secret || '',
      google_redirect_uri: req.body.google_redirect_uri || '',
      qris_payload: req.body.qris_payload || ''
    };
    if (req.files?.qris_image?.[0]) {
      const rel = '/uploads/' + path.basename(req.files.qris_image[0].path);
      payload.qris_image = rel;
    }
    await setSetting(payload);
    return res.json({ ok: true, message: 'Settings tersimpan' });
  } catch (e) {
    console.error(e); return res.status(500).json({ ok: false, error: 'Gagal simpan settings' });
  }
});

// Admin: force stop job
app.post('/admin/jobs/:id/stop', requireAdmin, async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM jobs WHERE id=?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ ok: false, error: 'Job tidak ditemukan' });
  const job = rows[0];
  const prc = livePrc.get(job.id);
  if (prc?.pid) { try { process.kill(prc.pid); } catch {} livePrc.delete(job.id); }
  await db.execute('UPDATE jobs SET status="stopped", ended_at=? WHERE id=?',[new Date(), job.id]);
  pushLog(job.id, '🚫 Streaming dihentikan oleh admin.');
  res.json({ ok: true, message: 'Job stopped' });
});

// ===== User Pages =====
app.get('/', requireAuth, async (req, res) => {
  const [list] = await db.execute('SELECT * FROM jobs WHERE user_id=? ORDER BY created_at DESC LIMIT 50', [req.session.userId]);
  res.render('index', { title: 'Dashboard', list });
});

app.get('/accounts', requireAuth, async (req, res) => {
  const [accounts] = await db.execute('SELECT * FROM accounts WHERE user_id=? ORDER BY id DESC', [req.session.userId]);
  res.render('accounts', { title: 'Accounts', accounts });
});

// ===== Connect Google (multi-account) =====
app.get('/connect/google', requireAuth, async (req, res) => {
  const client = await makeOAuthClientFromDB();
  const url = client.generateAuthUrl({ access_type:'offline', scope: SCOPES, prompt:'consent' });
  req.session.connectState = 'youtube';
  res.redirect(url);
});
app.get('/oauth2callback', requireAuth, async (req, res) => {
  try {
    if (req.session.connectState !== 'youtube') return res.redirect('/accounts');
    const client = await makeOAuthClientFromDB();
    const { tokens } = await client.getToken(req.query.code);
    client.setCredentials(tokens);

    const yt = google.youtube('v3');
    const me = await yt.channels.list({ auth: client, mine: true, part: 'snippet' });
    const label = me.data.items?.[0]?.snippet?.title || 'YouTube Account';

    await db.execute(
      `INSERT INTO accounts (user_id, provider, label, access_token, refresh_token, scope, token_type, expiry_date)
       VALUES (?,?,?,?,?,?,?,?)`,
      [req.session.userId, 'youtube', label, tokens.access_token || null, tokens.refresh_token || null,
       Array.isArray(tokens.scope)? tokens.scope.join(' ') : (tokens.scope || ''),
       tokens.token_type || 'Bearer', tokens.expiry_date || null]
    );
    res.redirect('/accounts');
  } catch (e) { console.error(e); res.status(500).send('OAuth error'); }
});
app.post('/accounts/:id/delete', requireAuth, async (req, res) => {
  await db.execute('DELETE FROM accounts WHERE id=? AND user_id=?', [req.params.id, req.session.userId]);
  res.redirect('/accounts');
});

// ===== New Live Page =====
app.get('/new', requireAuth, requireSubscription, async (req, res) => {
  const [accounts] = await db.execute('SELECT * FROM accounts WHERE user_id=? ORDER BY id DESC', [req.session.userId]);
  res.render('new', { title: 'Buat Live Baru', accounts });
});

// ===== Create Live (YouTube or Custom RTMP) =====
const uploadVideo = upload.single('video');
app.post('/api/live', requireAuth, requireSubscription, uploadVideo, async (req, res) => {
  try {
    const { mode, account_id, title, description, privacy, custom_rtmp, schedule_time, auto_start } = req.body;
    if (!req.file?.path) return res.status(400).json({ ok:false, error:'Video wajib diupload' });
    const filepath = req.file.path;
    const id = uuidv4();
    const now = new Date();

    let rtmp = null, broadcastId = null, streamId = null, accountIdNum = null;

    if (mode === 'youtube') {
      // Load account
      const [arows] = await db.execute('SELECT * FROM accounts WHERE id=? AND user_id=?', [Number(account_id), req.session.userId]);
      if (!arows.length) return res.status(400).json({ ok:false, error:'Akun YouTube tidak valid' });
      const acc = arows[0];

      const client = await makeOAuthClientFromDB();
      client.setCredentials({
        access_token: acc.access_token,
        refresh_token: acc.refresh_token,
        scope: acc.scope,
        token_type: acc.token_type,
        expiry_date: acc.expiry_date
      });
      client.on('tokens', async (t) => {
        if (t.access_token) await db.execute('UPDATE accounts SET access_token=?, expiry_date=? WHERE id=?', [t.access_token, t.expiry_date || null, acc.id]);
        if (t.refresh_token) await db.execute('UPDATE accounts SET refresh_token=? WHERE id=?', [t.refresh_token, acc.id]);
      });

      const youtube = google.youtube('v3');

      const broadcast = await youtube.liveBroadcasts.insert({
        auth: client,
        part: 'snippet,contentDetails,status',
        requestBody: {
          snippet: { title: (title||'Untitled').slice(0,95), description:(description||'').slice(0,4900), scheduledStartTime: new Date().toISOString() },
          status: { privacyStatus: ['public','unlisted','private'].includes(privacy)?privacy:'unlisted' },
          contentDetails: { enableAutoStart: true, enableAutoStop: true }
        }
      });

      const stream = await youtube.liveStreams.insert({
        auth: client,
        part: 'snippet,cdn',
        requestBody: {
          snippet: { title: `${(title||'Untitled').slice(0,80)} Stream` },
          cdn: { ingestionType: 'rtmp', resolution: '720p', frameRate: '30fps' }
        }
      });

      await youtube.liveBroadcasts.bind({
        auth: client,
        id: broadcast.data.id,
        part: 'id,contentDetails',
        streamId: stream.data.id
      });

      const ingest = stream.data.cdn?.ingestionInfo;
      if (!ingest?.ingestionAddress || !ingest?.streamName) throw new Error('Gagal ambil RTMP dari YouTube');

      rtmp = `${ingest.ingestionAddress}/${ingest.streamName}`;
      broadcastId = broadcast.data.id;
      streamId = stream.data.id;
      accountIdNum = acc.id;

    } else if (mode === 'custom') {
      if (!custom_rtmp || !/^rtmp(s)?:\/\//i.test(custom_rtmp)) return res.status(400).json({ ok:false, error:'RTMP tidak valid' });
      rtmp = custom_rtmp.trim();
    } else {
      return res.status(400).json({ ok:false, error:'Mode tidak valid' });
    }

    const sched = schedule_time ? new Date(schedule_time) : null;
    const willSchedule = !!sched;
    await db.execute(
      `INSERT INTO jobs (id,user_id,account_id,title,description,privacy,filepath,rtmp,broadcast_id,stream_id,status,schedule_time,auto_start,created_at,logs)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,JSON_ARRAY())`,
      [id, req.session.userId, accountIdNum || null, title || 'Untitled', description || '', privacy || 'unlisted', filepath, rtmp, broadcastId, streamId,
       willSchedule ? 'scheduled' : 'starting', willSchedule ? sched : null, auto_start ? 1 : 0, now]
    );

    if (!willSchedule) startFFmpeg({ id, filepath, rtmp });

    res.json({ ok:true, id, redirect: `/status/${id}` });
  } catch (e) {
    console.error('Create live error:', e?.response?.data || e);
    const msg = e?.response?.data?.error?.message || e.message || 'Terjadi kesalahan';
    res.status(500).json({ ok:false, error: msg });
  }
});

// ===== Status & Stop =====
app.get('/status/:id', requireAuth, async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM jobs WHERE id=? AND user_id=?', [req.params.id, req.session.userId]);
  if (!rows.length) return res.status(404).send('Job tidak ditemukan');
  const job = rows[0];
  job.logs = liveLogs.get(job.id) || [];
  res.render('status', { title: 'Status Stream', job, payment: null, settings: null });
});
app.post('/api/stop/:id', requireAuth, async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM jobs WHERE id=? AND user_id=?', [req.params.id, req.session.userId]);
  if (!rows.length) return res.status(404).json({ ok:false, error:'Job tidak ditemukan' });
  const job = rows[0];
  const p = livePrc.get(job.id);
  if (p?.pid) { try { process.kill(p.pid); } catch {} livePrc.delete(job.id); }
  await db.execute('UPDATE jobs SET status="stopped", ended_at=? WHERE id=?', [new Date(), job.id]);
  pushLog(job.id, 'Streaming dihentikan oleh user.');
  res.json({ ok:true });
});

// ===== Scheduler (tiap menit) =====
cron.schedule('* * * * *', async () => {
  try {
    const now = new Date();
    const [due] = await db.execute(
      `SELECT * FROM jobs 
       WHERE schedule_time IS NOT NULL AND auto_start=1 AND status='scheduled' AND schedule_time<=?`,
      [now]
    );
    for (const job of due) {
      pushLog(job.id, '⏰ Jadwal tiba, menjalankan FFmpeg otomatis...');
      await db.execute('UPDATE jobs SET status="starting" WHERE id=?', [job.id]);
      startFFmpeg({ id: job.id, filepath: job.filepath, rtmp: job.rtmp });
    }
  } catch (e) {
    console.error('Scheduler error:', e);
  }
});

// ===== FFmpeg Runner =====
function startFFmpeg({ id, filepath, rtmp }) {
  pushLog(id, 'Menjalankan FFmpeg...');
  db.execute('UPDATE jobs SET status="streaming", started_at=? WHERE id=?', [new Date(), id]).catch(()=>{});

  const args = [
    '-re', '-i', filepath,
    '-c:v', 'libx264',
    '-preset', 'veryfast',
    '-maxrate', '4500k',
    '-bufsize', '9000k',
    '-pix_fmt', 'yuv420p',
    '-g', '60',
    '-c:a', 'aac',
    '-b:a', '160k',
    '-ar', '44100',
    '-f', 'flv',
    rtmp
  ];

  const ff = spawn(FFMPEG_PATH, args, { windowsHide: true });
  livePrc.set(id, { pid: ff.pid });

  ff.stdout?.on('data', d => pushLog(id, String(d).trim()));
  ff.stderr?.on('data', d => pushLog(id, String(d).trim()));
  ff.on('error', err => pushLog(id, `FFmpeg error: ${err.message}`));
  ff.on('close', async (code) => {
    const status = code === 0 ? 'finished' : 'error';
    await db.execute('UPDATE jobs SET status=?, ended_at=? WHERE id=?', [status, new Date(), id]);
    pushLog(id, `FFmpeg exited with code ${code}`);
    livePrc.delete(id);
    // Opsional: hapus file setelah stream
    // try { fs.unlinkSync(filepath); } catch {}
  });
}

// ===== Start =====
server.listen(PORT, () => console.log(`Server running at ${BASE_URL}`));
