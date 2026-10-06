const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'my_super_secret_jwt_key_12345';

// مزامنة مبسطة
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255),
        password_hash VARCHAR(255),
        referral_code VARCHAR(50),
        referred_by VARCHAR(50),
        level INTEGER DEFAULT 1,
        is_verified BOOLEAN DEFAULT TRUE,
        verification_otp VARCHAR(10)
      );
    `);
    console.log("DB sync complete");
  } catch (err) {
    console.error("DB Init Error:", err.message);
  }
}
initDB();

function calculateLevel(count) {
  if (count >= 8) return 3;
  if (count >= 4) return 2;
  return 1;
}

// إنشاء الحساب
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, referral_code } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const checkUser = await pool.query('SELECT id FROM users WHERE email = $1', [cleanEmail]);
    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: 'البريد الإلكتروني مسجل مسبقاً' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const myReferral = Math.random().toString(36).substring(2, 8).toUpperCase();
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await pool.query(
      `INSERT INTO users (name, email, password, password_hash, referral_code, referred_by, is_verified, verification_otp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [name, cleanEmail, hashedPassword, hashedPassword, myReferral, referral_code ? referral_code.trim().toUpperCase() : null, true, otp]
    );

    res.json({ message: 'تم إنشاء الحساب بنجاح', otp });
  } catch (err) {
    res.status(500).json({ error: 'خطأ أثناء التسجيل: ' + err.message });
  }
});

// تفعيل الحساب OTP
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const cleanEmail = (email || '').toLowerCase().trim();
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [cleanEmail]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'المستخدم غير موجود' });

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'تم التفعيل بنجاح', token });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في تفعيل الرمز' });
  }
});

// تسجيل الدخول
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = (email || '').toLowerCase().trim();
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [cleanEmail]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'البريد أو كلمة المرور غير صحيحة' });

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password || user.password_hash);
    if (!isMatch) return res.status(400).json({ error: 'البريد أو كلمة المرور غير صحيحة' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في تسجيل الدخول' });
  }
});

// لوحة التحكم المضمونة
app.get('/api/dashboard', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'غير مصرح' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'الحساب غير موجود' });

    const user = userRes.rows[0];

    // جلب الإحالات بأمان
    let referrals = [];
    try {
      if (user.referral_code) {
        const refRes = await pool.query('SELECT name, email FROM users WHERE referred_by = $1', [user.referral_code]);
        referrals = refRes.rows || [];
      }
    } catch (e) {
      console.log("Referrals query notice:", e.message);
    }

    const referralCount = referrals.length;
    const currentLevel = calculateLevel(referralCount);

    res.json({
      user: {
        id: user.id,
        name: user.name || 'مستخدم',
        email: user.email,
        referral_code: user.referral_code || 'CODE123',
        level: currentLevel
      },
      referralCount,
      referrals
    });
  } catch (err) {
    console.error("Dashboard Error:", err.message);
    res.status(401).json({ error: 'جلسة منتهية أو غير صالحة' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
