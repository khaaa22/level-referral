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

// مزامنة وتعديل نوع عمود referred_by ليقبل النصوص والأرقام
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

    // تحويل عمود referred_by إلى نص لتفادي خطأ integer
    await pool.query(`
      ALTER TABLE users ALTER COLUMN referred_by TYPE VARCHAR(50) USING referred_by::varchar;
    `).catch(() => {});

    console.log("DB sync & migration complete");
  } catch (err) {
    console.error("DB Init Error:", err.message);
  }
}
initDB();

// حساب المستوى بناءً على عدد الإحالات (4 لكل مستوى)
function calculateLevel(count) {
  if (count >= 8) return 3;
  if (count >= 4) return 2;
  return 1;
}

// مسار التسجيل
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
    const refCodeToSave = referral_code && referral_code.trim() ? referral_code.trim().toUpperCase() : null;

    await pool.query(
      `INSERT INTO users (name, email, password, password_hash, referral_code, referred_by, is_verified, verification_otp)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [name, cleanEmail, hashedPassword, hashedPassword, myReferral, refCodeToSave, true, otp]
    );

    res.json({ message: 'تم إنشاء الحساب بنجاح', otp });
  } catch (err) {
    res.status(500).json({ error: 'خطأ أثناء التسجيل: ' + err.message });
  }
});

// مسار التحقق من OTP
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

// مسار تسجيل الدخول
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

// مسار لوحة التحكم
app.get('/api/dashboard', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'غير مصرح' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const userRes = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'الحساب غير موجود' });

    const user = userRes.rows[0];

    let referrals = [];
    try {
      if (user.referral_code) {
        const refRes = await pool.query('SELECT name, email FROM users WHERE referred_by = $1', [user.referral_code]);
        referrals = refRes.rows || [];
      }
    } catch (e) {
      console.log("Notice:", e.message);
    }

    const referralCount = referrals.length;
    const currentLevel = calculateLevel(referralCount);

    await pool.query('UPDATE users SET level = $1 WHERE id = $2', [currentLevel, user.id]).catch(() => {});

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
    res.status(401).json({ error: 'جلسة غير صالحة' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
