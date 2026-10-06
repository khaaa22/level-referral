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

// تهيئة قاعدة البيانات والتأكد من كل الأعمدة تلقائياً
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        referral_code VARCHAR(50) UNIQUE,
        referred_by VARCHAR(50),
        level INTEGER DEFAULT 1,
        is_verified BOOLEAN DEFAULT TRUE,
        verification_otp VARCHAR(10),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // إضافة الأعمدة إذا كان الجدول قديماً
    const columns = [
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(50) UNIQUE;",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by VARCHAR(50);",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS level INTEGER DEFAULT 1;",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT TRUE;",
      "ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_otp VARCHAR(10);"
    ];

    for (const col of columns) {
      await pool.query(col).catch(() => {});
    }

    console.log("Database initialized successfully");
  } catch (err) {
    console.error("DB Init Error:", err.message);
  }
}
initDB();

// مسار التسجيل
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, referral_code } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });
    }

    const checkUser = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: 'البريد الإلكتروني مسجل مسبقاً' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const myReferral = Math.random().toString(36).substring(2, 8).toUpperCase();
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await pool.query(
      `INSERT INTO users (name, email, password, referral_code, referred_by, is_verified, verification_otp)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [name, email.toLowerCase().trim(), hashedPassword, myReferral, referral_code || null, true, otp]
    );

    res.json({ message: 'تم إنشاء الحساب بنجاح', otp });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ error: 'خطأ في حفظ البيانات: ' + err.message });
  }
});

// مسار تفعيل OTP
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'المستخدم غير موجود' });
    }

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'تم الدخول بنجاح', token });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في التفعيل' });
  }
});

// مسار تسجيل الدخول
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

// مسار لوحة التحكم
app.get('/api/dashboard', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'غير مصرح' });

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const userRes = await pool.query('SELECT id, name, email, referral_code, level FROM users WHERE id = $1', [decoded.id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'الحساب غير موجود' });

    const user = userRes.rows[0];
    const countRes = await pool.query('SELECT COUNT(*) FROM users WHERE referred_by = $1', [user.referral_code]);

    res.json({
      user,
      referralCount: parseInt(countRes.rows[0].count, 10)
    });
  } catch (err) {
    res.status(401).json({ error: 'جلسة منتهية' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
