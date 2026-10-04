const express=require("express");
const path=require("path");
const crypto=require("crypto");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const {Pool}=require("pg");

const app=express();
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==="production"?{rejectUnauthorized:false}:false});
const SECRET=process.env.JWT_SECRET;
app.use(express.json());
app.use(express.static(path.join(__dirname,"public")));

async function init(){
 await pool.query(`CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  referral_code TEXT UNIQUE NOT NULL,
  referred_by INTEGER REFERENCES users(id),
  level INTEGER NOT NULL DEFAULT 1,
  referrals INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
 )`);
}
function publicUser(u){return {name:u.name,email:u.email,level:u.level,referrals:u.referrals,referral_code:u.referral_code};}
function makeToken(u){return jwt.sign({id:u.id},SECRET,{expiresIn:"7d"});}
function auth(req,res,next){
 try{
  const h=req.headers.authorization||"";
  if(!h.startsWith("Bearer ")) throw 0;
  req.user=jwt.verify(h.slice(7),SECRET); next();
 }catch(e){res.status(401).json({error:"جلسة الدخول منتهية، سجلي الدخول من جديد"});}
}

app.post("/api/register",async(req,res)=>{
 try{
  const {name,email,password,ref}=req.body;
  if(!name||!email||!password)return res.status(400).json({error:"املئي جميع الخانات"});
  if(password.length<6)return res.status(400).json({error:"كلمة السر يجب أن تكون 6 أحرف على الأقل"});
  const clean=email.trim().toLowerCase();
  const exists=await pool.query("SELECT id FROM users WHERE email=$1",[clean]);
  if(exists.rowCount)return res.status(409).json({error:"هذا البريد مسجل من قبل"});
  let parent=null;
  if(ref){
   const p=await pool.query("SELECT id,level,referrals FROM users WHERE referral_code=$1",[ref]);
   if(p.rowCount) parent=p.rows[0];
  }
  const code=crypto.randomBytes(6).toString("hex");
  const hash=await bcrypt.hash(password,12);
  const client=await pool.connect();
  try{
   await client.query("BEGIN");
   const ins=await client.query("INSERT INTO users(name,email,password_hash,referral_code,referred_by) VALUES($1,$2,$3,$4,$5) RETURNING *",
    [name.trim(),clean,hash,code,parent?parent.id:null]);
   if(parent){
    const newCount=parent.referrals+1;
    const nextLevel=parent.level+(newCount>=3?1:0);
    await client.query("UPDATE users SET referrals=$1,level=$2 WHERE id=$3",[newCount%3,nextLevel,parent.id]);
   }
   await client.query("COMMIT");
   const u=ins.rows[0];
   res.json({token:makeToken(u),user:publicUser(u)});
  }catch(e){await client.query("ROLLBACK");throw e}finally{client.release();}
 }catch(e){console.error(e);res.status(500).json({error:"حدث خطأ في الخادم"});}
});

app.post("/api/login",async(req,res)=>{
 try{
  const clean=(req.body.email||"").trim().toLowerCase();
  const q=await pool.query("SELECT * FROM users WHERE email=$1",[clean]);
  if(!q.rowCount||!(await bcrypt.compare(req.body.password||"",q.rows[0].password_hash)))
   return res.status(401).json({error:"البريد الإلكتروني أو كلمة السر غير صحيحة"});
  res.json({token:makeToken(q.rows[0]),user:publicUser(q.rows[0])});
 }catch(e){res.status(500).json({error:"حدث خطأ في الخادم"});}
});

app.get("/api/me",auth,async(req,res)=>{
 const q=await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id]);
 if(!q.rowCount)return res.status(404).json({error:"المستخدم غير موجود"});
 res.json({user:publicUser(q.rows[0])});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
const port=process.env.PORT||3000;
init().then(()=>app.listen(port,()=>console.log("Server on "+port))).catch(e=>{console.error(e);process.exit(1)});
