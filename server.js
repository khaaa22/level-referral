const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const SECRET = process.env.JWT_SECRET || "super_secret_jwt_key_12345";

// إعداد خدمة الإيميل
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS ? process.env.EMAIL_PASS.replace(/\s+/g, '') : ""
  }
});

// ترقية وضبط جداول قاعدة البيانات تلقائياً
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(150) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        referral_code VARCHAR(50) UNIQUE,
        referred_by VARCHAR(50),
        level INT DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // إضافة الأعمدة إن كانت مفقودة لحل خطأ missing column نهائياً
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_otp VARCHAR(20);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_code VARCHAR(20);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS otp_expires TIMESTAMP;`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(50);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by VARCHAR(50);`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS level INT DEFAULT 1;`);

    console.log("Database initialized and columns synchronized successfully.");
  } catch (err) {
    console.error("Database Init Error:", err.message);
  }
}
initDB();

// 1. تسجيل مستخدم جديد
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, referral_code } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: "جميع الحقول مطلوبة" });
    }

    const cleanEmail = email.toLowerCase().trim();
    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [cleanEmail]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: "البريد الإلكتروني مسجل مسبقاً، يمكنك تسجيل الدخول" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 20 * 60 * 1000); // 20 دقيقة
    const myReferralCode = "REF-" + crypto.randomBytes(3).toString("hex").toUpperCase();

    await pool.query(
      `INSERT INTO users (name, email, password, verification_otp, otp_code, otp_expires, referral_code, referred_by, is_verified)
       VALUES ($1, $2, $3, $4, $4, $5, $6, $7, false)`,
      [name.trim(), cleanEmail, hashedPassword, otp, otpExpires, myReferralCode, referral_code || null]
    );

    // محاولة إرسال الإيميل
    try {
      if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: cleanEmail,
          subject: "كود تفعيل حسابك",
          text: `كود التحقق الخاص بك هو: ${otp}`
        });
      }
    } catch (mailErr) {
      console.log("Mail delivery notice:", mailErr.message);
    }

    console.log(`[OTP] Generated for ${cleanEmail}: ${otp}`);
    
    // إرجاع الكود مع الرسالة لضمان التفعيل الفوري
    res.json({
      success: true,
      message: `تم إنشاء الحساب! رمز التحقق هو: [ ${otp} ]`,
      otp: otp
    });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ error: "حدث خطأ أثناء إنشاء الحساب، يرجى المحاولة مجدداً" });
  }
});

// 2. التحقق من الرمز
app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ error: "البريد الإلكتروني والرمز مطلوبان" });
    }

    const cleanEmail = email.toLowerCase().trim();
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [cleanEmail]);
    
    if (userRes.rows.length === 0) {
      return res.status(400).json({ error: "الحساب غير موجود" });
    }

    const user = userRes.rows[0];
    const storedOtp = user.verification_otp || user.otp_code;

    if (storedOtp !== otp.trim()) {
      return res.status(400).json({ error: "كود التحقق غير صحيح" });
    }

    await pool.query(
      "UPDATE users SET is_verified = true, verification_otp = NULL, otp_code = NULL WHERE id = $1",
      [user.id]
    );

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: "7d" });
    res.json({
      success: true,
      token,
      user: { id: user.id, name: user.name, email: user.email, level: user.level }
    });
  } catch (err) {
    console.error("Verify Error:", err);
    res.status(500).json({ error: "تعذر التحقق من الرمز" });
  }
});

// 3. تسجيل الدخول
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = email.toLowerCase().trim();
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [cleanEmail]);
    
    if (userRes.rows.length === 0) {
      return res.status(400).json({ error: "بيانات الدخول غير صحيحة" });
    }

    const user = userRes.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: "بيانات الدخول غير صحيحة" });
    }

    if (!user.is_verified) {
      return res.status(403).json({ error: "يرجى تفعيل الحساب أولاً بواسطة الكود" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: "7d" });
    res.json({
      success: true,
      token,
      user: { id: user.id, name: user.name, email: user.email, level: user.level }
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "خطأ في تسجيل الدخول" });
  }
});

// 4. بيانات لوحة التحكم والمستويات
app.get("/api/dashboard", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "غير مصرح" });

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, SECRET);

    const userRes = await pool.query("SELECT id, name, email, referral_code, level FROM users WHERE id = $1", [decoded.id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: "المستخدم غير موجود" });

    const user = userRes.rows[0];
    const referralsRes = await pool.query(
      "SELECT id, name, email, level, created_at FROM users WHERE referred_by = $1",
      [user.referral_code]
    );

    const count = referralsRes.rows.length;
    let calculatedLevel = 1;
    if (count >= 8) calculatedLevel = 3;
    else if (count >= 4) calculatedLevel = 2;

    if (calculatedLevel !== user.level) {
      await pool.query("UPDATE users SET level = $1 WHERE id = $2", [calculatedLevel, user.id]);
      user.level = calculatedLevel;
    }

    res.json({
      user,
      referrals: referralsRes.rows,
      referralCount: count
    });
  } catch (err) {
    console.error("Dashboard Error:", err);
    res.status(401).json({ error: "جلسة منتهية" });
  }
});

// تقديم الواجهة
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
