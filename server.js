require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const JWT_SECRET = process.env.JWT_SECRET || 'lutfen-degistir';

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

// ---- AUTH ----

app.post('/api/login', async (req, res) => {
  try {
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
    const token = jwt.sign(
      { id: seller.id, phone: seller.phone, name: seller.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: true,
    });
    res.json({ ok: true, name: seller.name });
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
  res.json({ name: req.user.name, phone: req.user.phone });
});

// ---- LEADS ----

app.get('/api/leads', auth, async (req, res) => {
  try {
    const { status, q } = req.query;
    const conditions = [];
    const params = [];

    if (status && status !== 'all') {
      if (status === 'bekliyor') {
        conditions.push(`(call_status IS NULL OR call_status = 'bekliyor')`);
      } else {
        params.push(status);
        conditions.push(`call_status = $${params.length}`);
      }
    }
    if (q) {
      params.push(`%${q}%`);
      conditions.push(`(customer_name ILIKE $${params.length} OR phone ILIKE $${params.length} OR ilan_arac ILIKE $${params.length})`);
    }

    const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';
    const { rows } = await pool.query(
      `SELECT id, session_id, customer_name, phone, ilan_arac, butce, takas, zaman,
              created_at, call_status, call_note, updated_at
       FROM leads
       ${where}
       ORDER BY created_at DESC
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
        COUNT(*) AS toplam,
        COUNT(*) FILTER (WHERE call_status IS NULL OR call_status = 'bekliyor') AS bekliyor,
        COUNT(*) FILTER (WHERE call_status = 'ilgilendi') AS ilgilendi,
        COUNT(*) FILTER (WHERE call_status = 'dusunuyor') AS dusunuyor,
        COUNT(*) FILTER (WHERE call_status = 'ilgilenmedi') AS ilgilenmedi,
        COUNT(*) FILTER (WHERE call_status = 'ulasimadi') AS ulasimadi
      FROM leads
    `);
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Özet alınamadı' });
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
