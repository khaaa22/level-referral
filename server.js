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

const SECRET = process.env.JWT_SECRET || "fallback_secret_key_12345";

// إعداد خدمة البريد
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// إنشاء الجداول تلقائياً إن لم تكن موجودة
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(150) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        is_verified BOOLEAN DEFAULT FALSE,
        otp_code VARCHAR(10),
        otp_expires TIMESTAMP,
        referral_code VARCHAR(50) UNIQUE,
        referred_by VARCHAR(50),
        level INT DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("Database initialized successfully");
  } catch (err) {
    console.error("Database initialization error:", err);
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

    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase().trim()]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: "البريد الإلكتروني مسجل مسبقاً" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 دقيقة
    const myReferralCode = "REF-" + crypto.randomBytes(3).toString("hex").toUpperCase();

    await pool.query(
      `INSERT INTO users (name, email, password, otp_code, otp_expires, referral_code, referred_by, is_verified)
       VALUES ($1, $2, $3, $4, $5, $6, $7, false)`,
      [name, email.toLowerCase().trim(), hashedPassword, otp, otpExpires, myReferralCode, referral_code || null]
    );

    // محاولة إرسال الإيميل مع عدم تعطيل الرد في حال الفشل
    try {
      if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: email,
          subject: "كود التحقق لتفعيل حسابك",
          text: `كود التحقق الخاص بك هو: ${otp}`
        });
      }
    } catch (mailErr) {
      console.log("Mail send notice:", mailErr.message);
    }

    console.log(`[OTP Generated] Email: ${email} | Code: ${otp}`);
    res.json({
      success: true,
      message: `تم إنشاء الحساب! كود التحقق هو: [ ${otp} ] (تم إظهاره لتسهيل التجربة فوراً)`,
      otp: otp
    });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ error: "حدث خطأ في السيرفر" });
  }
});

// 2. التحقق من كود الـ OTP
app.post("/api/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase().trim()]);
    
    if (userRes.rows.length === 0) {
      return res.status(400).json({ error: "المستخدم غير موجود" });
    }

    const user = userRes.rows[0];
    if (user.otp_code !== otp.trim()) {
      return res.status(400).json({ error: "كود التحقق غير صحيح" });
    }

    if (new Date() > new Date(user.otp_expires)) {
      return res.status(400).json({ error: "انتهت صلاحية الكود" });
    }

    await pool.query("UPDATE users SET is_verified = true, otp_code = NULL WHERE id = $1", [user.id]);

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: "7d" });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, level: user.level } });
  } catch (err) {
    console.error("Verify OTP Error:", err);
    res.status(500).json({ error: "حدث خطأ في السيرفر" });
  }
});

// 3. تسجيل الدخول
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const userRes = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase().trim()]);
    
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
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, level: user.level } });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "حدث خطأ في السيرفر" });
  }
});

// 4. استرجاع بيانات المستخدم والإحالات
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

    // حساب المستوى تلقائياً حسب عدد الإحالات (كل 4 إحالات ترفع مستوى)
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
    res.status(401).json({ error: "جلسة غير صالحة" });
  }
});

// معالجة الصفحات
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
