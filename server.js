require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---- GÜVENLİK HEADER'LARI ----
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET === 'lutfen-degistir' || JWT_SECRET === 'uzun_ve_rastgele_bir_metin_buraya') {
  console.error('HATA: JWT_SECRET ortam değişkeni ayarlanmamış veya varsayılan değerde! Sunucu güvenli değil, durduruluyor.');
  process.exit(1);
}

// ---- BASİT RATE LIMIT (login için) ----
// IP başına 15 dakikada en fazla 20 hatalı deneme.
const loginAttempts = new Map(); // ip -> { count, firstAttempt }
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 20;

// ---- GENEL API RATE LIMIT ----
// IP başına 15 dakikada en fazla 500 API isteği.
const apiAttempts = new Map();
const API_RATE_MAX = 500;

function checkApiRateLimit(ip) {
  const now = Date.now();
  const entry = apiAttempts.get(ip);
  if (!entry || now - entry.firstAttempt > RATE_LIMIT_WINDOW_MS) {
    apiAttempts.set(ip, { count: 1, firstAttempt: now });
    return { blocked: false };
  }
  if (entry.count >= API_RATE_MAX) return { blocked: true };
  entry.count += 1;
  return { blocked: false };
}

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now - entry.firstAttempt > RATE_LIMIT_WINDOW_MS) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now });
    return { blocked: false };
  }
  if (entry.count >= RATE_LIMIT_MAX) {
    const waitMs = RATE_LIMIT_WINDOW_MS - (now - entry.firstAttempt);
    return { blocked: true, waitMinutes: Math.ceil(waitMs / 60000) };
  }
  entry.count += 1;
  return { blocked: false };
}

function resetRateLimit(ip) {
  loginAttempts.delete(ip);
}

// Eski kayıtları arada bir temizle (bellek şişmesin)
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts.entries()) {
    if (now - entry.firstAttempt > RATE_LIMIT_WINDOW_MS) loginAttempts.delete(ip);
  }
  for (const [ip, entry] of apiAttempts.entries()) {
    if (now - entry.firstAttempt > RATE_LIMIT_WINDOW_MS) apiAttempts.delete(ip);
  }
}, 10 * 60 * 1000);

// Genel API rate limit middleware (login endpoint'i kendi rate limit'ini kullanıyor)
app.use('/api/', (req, res, next) => {
  if (req.path === '/login') return next();
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  const limit = checkApiRateLimit(ip);
  if (limit.blocked) {
    return res.status(429).json({ error: 'Günlük istek limiti aşıldı. Lütfen bekleyin.' });
  }
  next();
});

const STATUS_LABELS = {
  bekliyor: 'Bekliyor',
  ilgilendi: 'İlgilendi',
  dusunuyor: 'Düşünüyor',
  ilgilenmedi: 'İlgilenmedi',
  ulasimadi: 'Ulaşamadı',
};

function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Giriş yapmalısınız' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Oturum geçersiz, tekrar giriş yapın' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Bu işlem için yönetici (Admin) yetkisi gerekiyor' });
  }
  next();
}

// ---- AUTH ----

app.post('/api/login', async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
    const limit = checkRateLimit(ip);
    if (limit.blocked) {
      return res.status(429).json({ error: `Çok fazla hatalı deneme. ${limit.waitMinutes} dakika sonra tekrar deneyin.` });
    }

    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.status(400).json({ error: 'Telefon ve şifre gerekli' });
    }
    const { rows } = await pool.query('SELECT * FROM sellers WHERE phone = $1', [phone.trim()]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Telefon veya şifre hatalı' });
    }
    const seller = rows[0];
    const ok = await bcrypt.compare(password, seller.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Telefon veya şifre hatalı' });
    }
    resetRateLimit(ip);
    const userRole = seller.role || 'seller';
    const token = jwt.sign(
      { id: seller.id, phone: seller.phone, name: seller.name, role: userRole },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: true,
    });
    res.json({ ok: true, name: seller.name, phone: seller.phone, role: userRole });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Sunucu hatası' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ id: req.user.id, name: req.user.name, phone: req.user.phone, role: req.user.role || 'seller' });
});

app.post('/api/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Tüm alanları doldurun' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Yeni şifre en az 8 karakter olmalıdır' });
    }
    const { rows } = await pool.query('SELECT password_hash FROM sellers WHERE id = $1', [req.user.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    
    const ok = await bcrypt.compare(currentPassword, rows[0].password_hash);
    if (!ok) return res.status(400).json({ error: 'Mevcut şifreniz hatalı' });

    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE sellers SET password_hash = $1 WHERE id = $2', [newHash, req.user.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Şifre değiştirilemedi' });
  }
});

// ---- KULLANICI YÖNETİMİ (Sadece Admin) ----

app.get('/api/users', auth, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id, name, phone, role, created_at FROM sellers ORDER BY id ASC');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kullanıcılar alınamadı' });
  }
});

app.post('/api/users', auth, requireAdmin, async (req, res) => {
  try {
    const { name, phone, password, role } = req.body;
    if (!name || !phone || !password) {
      return res.status(400).json({ error: 'Ad, telefon ve şifre alanları zorunludur' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Şifre en az 8 karakter olmalıdır' });
    }
    const cleanPhone = phone.trim();
    const existing = await pool.query('SELECT id FROM sellers WHERE phone = $1', [cleanPhone]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Bu telefon numarası zaten kayıtlı' });
    }
    const userRole = role === 'admin' ? 'admin' : 'seller';
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO sellers (name, phone, password_hash, role) VALUES ($1, $2, $3, $4)
       RETURNING id, name, phone, role, created_at`,
      [name.trim(), cleanPhone, hash, userRole]
    );
    res.json({ ok: true, user: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kullanıcı eklenemedi' });
  }
});

app.delete('/api/users/:id', auth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (String(id) === String(req.user.id)) {
      return res.status(400).json({ error: 'Kendi admin hesabınızı silemezsiniz' });
    }
    const { rowCount } = await pool.query('DELETE FROM sellers WHERE id = $1', [id]);
    if (rowCount === 0) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kullanıcı silinemedi' });
  }
});

// ---- 6 Aylık Otomatik Çöp Kutusu Temizleme ----
async function purgeOldTrash() {
  try {
    const res = await pool.query("DELETE FROM leads WHERE deleted_at IS NOT NULL AND deleted_at < now() - INTERVAL '180 days'");
    if (res.rowCount > 0) {
      console.log(`[Purge] ${res.rowCount} adet 6 aydan eski silinmiş kayıt kalıcı olarak temizlendi.`);
    }
  } catch (err) {
    console.error('[Purge Error]', err);
  }
}
purgeOldTrash();
setInterval(purgeOldTrash, 24 * 60 * 60 * 1000);

// ---- LEADS ----

app.get('/api/leads', auth, async (req, res) => {
  try {
    const { status, q } = req.query;
    const conditions = [];
    const params = [];

    if (status === 'trash') {
      conditions.push(`l.deleted_at IS NOT NULL`);
    } else {
      conditions.push(`l.deleted_at IS NULL`);
      if (status && status !== 'all') {
        if (status === 'bekliyor') {
          conditions.push(`(l.call_status IS NULL OR l.call_status = 'bekliyor')`);
        } else {
          params.push(status);
          conditions.push(`l.call_status = $${params.length}`);
        }
      }
    }

    if (q) {
      params.push(`%${q}%`);
      conditions.push(`(l.customer_name ILIKE $${params.length} OR l.phone ILIKE $${params.length} OR l.ilan_arac ILIKE $${params.length})`);
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const { rows } = await pool.query(
      `SELECT l.id, l.session_id, l.customer_name, l.phone, l.ilan_arac, l.butce, l.takas, l.zaman,
              l.created_at, l.call_status, l.call_note, l.updated_at, l.conversation_snapshot, l.deleted_at,
              (SELECT r.remind_at FROM reminders r
                WHERE r.phone = l.phone AND r.sent = false
                ORDER BY r.remind_at ASC LIMIT 1) AS next_reminder
       FROM leads l
       ${where}
       ORDER BY l.deleted_at DESC NULLS LAST, l.created_at DESC
       LIMIT 300`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kayıtlar alınamadı' });
  }
});

app.get('/api/stats', auth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE deleted_at IS NULL) AS toplam,
        COUNT(*) FILTER (WHERE deleted_at IS NULL AND (call_status IS NULL OR call_status = 'bekliyor')) AS bekliyor,
        COUNT(*) FILTER (WHERE deleted_at IS NULL AND call_status = 'ilgilendi') AS ilgilendi,
        COUNT(*) FILTER (WHERE deleted_at IS NULL AND call_status = 'dusunuyor') AS dusunuyor,
        COUNT(*) FILTER (WHERE deleted_at IS NULL AND call_status = 'ilgilenmedi') AS ilgilenmedi,
        COUNT(*) FILTER (WHERE deleted_at IS NULL AND call_status = 'ulasimadi') AS ulasimadi,
        COUNT(*) FILTER (WHERE deleted_at IS NOT NULL) AS trash,
        ROUND(
          COUNT(*) FILTER (WHERE deleted_at IS NULL AND call_status = 'ilgilendi')::numeric
          / NULLIF(COUNT(*) FILTER (WHERE deleted_at IS NULL), 0) * 100, 1
        ) AS donusum_orani
      FROM leads
    `);
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Özet alınamadı' });
  }
});

app.post('/api/leads/:id/trash', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      `UPDATE leads SET deleted_at = now() WHERE id = $1 RETURNING id, deleted_at`,
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Kayıt bulunamadı' });
    res.json({ ok: true, lead: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Çöp kutusuna taşınamadı' });
  }
});

app.post('/api/leads/:id/restore', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const { rows } = await pool.query(
      `UPDATE leads SET deleted_at = NULL WHERE id = $1 RETURNING id, deleted_at`,
      [id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Kayıt bulunamadı' });
    res.json({ ok: true, lead: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Geri yüklenemedi' });
  }
});

app.patch('/api/leads/:id', auth, async (req, res) => {
  try {
    const { id } = req.params;
    const { call_status, call_note } = req.body;

    if (call_status !== undefined && !(call_status === null || STATUS_LABELS[call_status])) {
      return res.status(400).json({ error: 'Geçersiz durum' });
    }

    const sets = [];
    const params = [];

    if (call_status !== undefined) {
      params.push(call_status);
      sets.push(`call_status = $${params.length}`);
    }
    if (call_note !== undefined) {
      params.push(call_note);
      sets.push(`call_note = $${params.length}`);
    }
    sets.push(`updated_at = now()`);

    params.push(id);
    const { rows } = await pool.query(
      `UPDATE leads SET ${sets.join(', ')} WHERE id = $${params.length}
       RETURNING id, call_status, call_note, updated_at`,
      params
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Kayıt bulunamadı' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Güncellenemedi' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CRM panel ${PORT} portunda çalışıyor`));
