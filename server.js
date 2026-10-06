const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const SECRET = process.env.JWT_SECRET || "fallback_secret_key_123";

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

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, referrerCode } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: "جميع الحقول مطلوبة" });
    }

    const check = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (check.rows.length > 0) {
      return res.status(400).json({ message: "البريد مسجل مسبقاً" });
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

    const inserted = await pool.query(
      `INSERT INTO users (name, email, password_hash, referral_code, referred_by)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, level, referral_code, referral_count`,
      [name, email, hash, code, referredBy]
    );

    const newUser = inserted.rows[0];

    // تحديث إحالات الداعي والترقية عند 4 إحالات
    if (referredBy) {
      const parent = await pool.query("SELECT id, level, referral_count FROM users WHERE id = $1", [referredBy]);
      if (parent.rows.length > 0) {
        let p = parent.rows[0];
        let newCount = p.referral_count + 1;
        let newLevel = p.level;

        // الانتقال للمستوى التالي عند اكتمال 4 إحالات (حتى المستوى 3)
        if (newCount >= 4 && newLevel < 3) {
          newLevel += 1;
          newCount = 0; // إعادة التصفير لبدء لوحة المستوى الجديد
        }

        await pool.query("UPDATE users SET referral_count = $1, level = $2 WHERE id = $3", [newCount, newLevel, p.id]);
      }
    }

    const token = makeToken(newUser);
    res.json({ token, user: newUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "حدث خطأ في الخادم" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "بيانات الدخول غير صحيحة" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(400).json({ message: "بيانات الدخول غير صحيحة" });
    }

    const token = makeToken(user);
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        level: user.level,
        referral_code: user.referral_code,
        referral_count: user.referral_count
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "حدث خطأ في الخادم" });
  }
});

app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const u = await pool.query("SELECT id, name, email, level, referral_code, referral_count FROM users WHERE id = $1", [req.user.id]);
    if (u.rows.length === 0) return res.status(404).json({ message: "المستخدم غير موجود" });

    const refs = await pool.query("SELECT name, email, level, created_at FROM users WHERE referred_by = $1 ORDER BY id ASC LIMIT 4", [req.user.id]);

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
