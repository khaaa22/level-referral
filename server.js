const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const nodemailer = require("nodemailer");

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const SECRET = process.env.JWT_SECRET || "fallback_secret_key_123";

// إعداد خدمة إرسال الإيميلات
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      referral_code TEXT UNIQUE NOT NULL,
      referred_by INTEGER REFERENCES users(id),
      level INTEGER NOT NULL DEFAULT 1,
      referral_count INTEGER NOT NULL DEFAULT 0,
      is_verified BOOLEAN DEFAULT FALSE,
      verification_otp TEXT,
      reset_otp TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}
init().catch(console.error);

function makeToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: "7d" });
}

function authMiddleware(req, res, next) {
  const h = req.headers["authorization"];
  if (!h) return res.status(401).json({ message: "غير مصرح" });
  const token = h.split(" ")[1];
  try {
    const payload = jwt.verify(token, SECRET);
    req.user = payload;
    next();
  } catch (e) {
    res.status(401).json({ message: "جلسة غير صالحة" });
  }
}

// 1. بدء التسجيل وإرسال كود التحقق
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, referrerCode } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: "جميع الحقول مطلوبة" });
    }

    const check = await pool.query("SELECT id, is_verified FROM users WHERE email = $1", [email]);
    if (check.rows.length > 0) {
      if (check.rows[0].is_verified) {
        return res.status(400).json({ message: "البريد الإلكتروني مسجل ومفعل مسبقاً" });
      }
      await pool.query("DELETE FROM users WHERE email = $1", [email]);
    }

    let referredBy = null;
    if (referrerCode) {
      const refUser = await pool.query("SELECT id FROM users WHERE referral_code = $1", [referrerCode]);
      if (refUser.rows.length > 0) {
        referredBy = refUser.rows[0].id;
      }
    }

    const hash = await bcrypt.hash(password, 10);
    const code = crypto.randomBytes(6).toString("hex");
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await pool.query(
      `INSERT INTO users (name, email, password_hash, referral_code, referred_by, verification_otp, is_verified)
       VALUES ($1, $2, $3, $4, $5, $6, FALSE)`,
      [name, email, hash, code, referredBy, otp]
    );

    // إرسال الكود إلى بريد المستخدم
    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      await transporter.sendMail({
        from: `"نظام المستويات" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "كود التحقق لتفعيل حسابك",
        text: `رمز التحقق الخاص بك هو: ${otp}`
      });
    }

    res.json({ message: "تم إرسال كود التحقق إلى بريدك الإلكتروني", email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "حدث خطأ في الخادم" });
  }
});

// 2. التحقق من كود التسجيل وتفعيل الحساب
app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email = $1 AND verification_otp = $2", [email, otp]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "رمز التحقق غير صحيح" });
    }

    const user = result.rows[0];
    await pool.query("UPDATE users SET is_verified = TRUE, verification_otp = NULL WHERE id = $1", [user.id]);

    // احتساب الإحالة للشخص الداعي والترقية عند 4 إحالات
    if (user.referred_by) {
      const parent = await pool.query("SELECT id, level, referral_count FROM users WHERE id = $1", [user.referred_by]);
      if (parent.rows.length > 0) {
        let p = parent.rows[0];
        let newCount = p.referral_count + 1;
        let newLevel = p.level;

        if (newCount >= 4 && newLevel < 3) {
          newLevel += 1;
          newCount = 0;
        }

        await pool.query("UPDATE users SET referral_count = $1, level = $2 WHERE id = $3", [newCount, newLevel, p.id]);
      }
    }

    const token = makeToken(user);
    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "حدث خطأ في الخادم" });
  }
});

// 3. تسجيل الدخول
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "بيانات الدخول غير صحيحة" });
    }

    const user = result.rows[0];
    if (!user.is_verified) {
      return res.status(400).json({ message: "الحساب غير مؤكد بعد. يرجى تأكيد بريدك أولاً" });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(400).json({ message: "بيانات الدخول غير صحيحة" });
    }

    const token = makeToken(user);
    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "حدث خطأ في الخادم" });
  }
});

// 4. طلب كود نسيت كلمة المرور
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const result = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "البريد الإلكتروني غير موجود" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await pool.query("UPDATE users SET reset_otp = $1 WHERE email = $2", [otp, email]);

    if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
      await transporter.sendMail({
        from: `"نظام المستويات" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: "رمز إعادة تعيين كلمة المرور",
        text: `رمز إعادة تعيين كلمة المرور هو: ${otp}`
      });
    }

    res.json({ message: "تم إرسال رمز إعادة التعيين إلى بريدك الإلكتروني" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "حدث خطأ في الخادم" });
  }
});

// 5. تعيين كلمة مرور جديدة بالكود
app.post("/api/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    const result = await pool.query("SELECT id FROM users WHERE email = $1 AND reset_otp = $2", [email, otp]);

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "رمز التحقق غير صحيح" });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query("UPDATE users SET password_hash = $1, reset_otp = NULL WHERE email = $2", [hash, email]);

    res.json({ message: "تم تغيير كلمة المرور بنجاح. يمكنك الآن تسجيل الدخول" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "حدث خطأ في الخادم" });
  }
});

// 6. جلب بيانات اللوحة
app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const u = await pool.query("SELECT id, name, email, level, referral_code, referral_count FROM users WHERE id = $1", [req.user.id]);
    if (u.rows.length === 0) return res.status(404).json({ message: "المستخدم غير موجود" });

    const refs = await pool.query(
      "SELECT name, email, level, created_at FROM users WHERE referred_by = $1 AND is_verified = TRUE ORDER BY id ASC LIMIT 4",
      [req.user.id]
    );

    res.json({ user: u.rows[0], referrals: refs.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "حدث خطأ في الخادم" });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

