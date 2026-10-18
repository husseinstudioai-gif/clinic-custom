'use strict';
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const prod = process.env.NODE_ENV === 'production';
if (prod && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error('In production, SESSION_SECRET must be set to a random value of at least 32 characters.');
}
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex');
const db = new Database(path.join(__dirname, 'clinic-custom.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 display_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','reception','doctor','finance','lab')),
 avatar_data TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS records (
 id INTEGER PRIMARY KEY, module TEXT NOT NULL, data TEXT NOT NULL,
 created_by INTEGER NOT NULL, updated_by INTEGER NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(created_by) REFERENCES users(id), FOREIGN KEY(updated_by) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS records_module_idx ON records(module, id DESC);
CREATE TABLE IF NOT EXISTS audit_log (
 id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, module TEXT,
 record_id INTEGER, ip TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
// Safe schema migration for databases created by earlier Clinic Custom versions.
const userColumns = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
if (!userColumns.includes('avatar_data')) db.exec('ALTER TABLE users ADD COLUMN avatar_data TEXT');

const roles = {
 admin: ['patients','appointments','finance','prescriptions','lab','insurance','reports','users'],
 reception: ['patients','appointments','insurance','reports'],
 doctor: ['patients','appointments','prescriptions','lab','reports'],
 finance: ['finance','insurance','reports'],
 lab: ['lab','patients','reports']
};
const modules = {
 patients: {label:'پرونده بیماران', icon:'♙', fields:[['name','نام و نام خانوادگی','text',true],['phone','شماره تماس','tel',false],['nationalId','کد شناسایی','text',false],['birthDate','تاریخ تولد','text',false],['allergies','حساسیت‌ها','textarea',false],['notes','یادداشت پرونده','textarea',false]]},
 appointments: {label:'نوبت‌دهی',icon:'▦',fields:[['patient','نام بیمار','text',true],['doctor','پزشک / متخصص','text',true],['date','تاریخ (مثلاً 1405/07/25)','text',true],['time','ساعت','text',true],['service','خدمت زیبایی','text',true],['status','وضعیت','select',true,['ثبت‌شده','تأییدشده','انجام‌شده','لغوشده']],['notes','توضیحات','textarea',false]]},
 finance: {label:'امور مالی',icon:'↗',fields:[['patient','نام بیمار','text',true],['kind','نوع تراکنش','select',true,['دریافت','هزینه','بدهی']],['amount','مبلغ (تومان)','number',true],['method','روش پرداخت','select',false,['نقدی','کارت‌خوان','انتقال بانکی','بیمه']],['date','تاریخ','text',true],['description','شرح','textarea',false]]},
 prescriptions: {label:'دستورات پزشک',icon:'✚',fields:[['patient','نام بیمار','text',true],['doctor','پزشک','text',true],['date','تاریخ','text',true],['procedure','خدمت / روش درمان','text',true],['instructions','دستورات و مراقبت‌ها','textarea',true],['followup','زمان پیگیری','text',false]]},
 lab: {label:'آزمایشگاه',icon:'⌁',fields:[['patient','نام بیمار','text',true],['test','نام آزمایش / درخواست','text',true],['date','تاریخ درخواست','text',true],['status','وضعیت','select',true,['در انتظار','در حال انجام','آماده']],['result','نتیجه / توضیح','textarea',false]]},
 insurance: {label:'بیمه و صورتحساب',icon:'▤',fields:[['patient','نام بیمار','text',true],['provider','شرکت بیمه','text',true],['policy','شماره بیمه‌نامه','text',false],['invoice','شماره صورتحساب','text',true],['amount','مبلغ (تومان)','number',true],['status','وضعیت','select',true,['در انتظار','تأییدشده','ردشده','تسویه‌شده']]]}
};
const safeText = (v, max=2000) => String(v ?? '').trim().slice(0,max);
function audit(req, action, module=null, recordId=null) {
  db.prepare('INSERT INTO audit_log(user_id,action,module,record_id,ip) VALUES(?,?,?,?,?)')
    .run(req.session?.user?.id || null, action, module, recordId, safeText(req.ip,100));
}
function requireAuth(req,res,next) { if (!req.session.user) return res.status(401).json({error:'ابتدا وارد حساب کاربری شوید.'}); next(); }
function allow(module) { return (req,res,next) => { if (!req.session.user || !roles[req.session.user.role]?.includes(module)) return res.status(403).json({error:'دسترسی به این بخش مجاز نیست.'}); next(); }; }
function validateRecord(module, body) {
  const def = modules[module]; if (!def || !body || typeof body !== 'object' || Array.isArray(body)) return {error:'اطلاعات نامعتبر است.'};
  const data = {};
  for (const [key,label,type,required,options] of def.fields) {
    let value = safeText(body[key], type === 'textarea' ? 4000 : 250);
    if (required && !value) return {error:`فیلد «${label}» الزامی است.`};
    if (type === 'number' && value && (!/^\d{1,12}(\.\d{1,2})?$/.test(value) || Number(value)<0)) return {error:`مقدار «${label}» معتبر نیست.`};
    if (type === 'select' && value && !options.includes(value)) return {error:`گزینه «${label}» معتبر نیست.`};
    if (key === 'phone' && value && !/^[+\d\s()-]{7,24}$/.test(value)) return {error:'شماره تماس معتبر نیست.'};
    data[key] = value;
  }
  return {data};
}

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],scriptSrc:["'self'"],imgSrc:["'self'","data:"],connectSrc:["'self'"],objectSrc:["'none'"],frameAncestors:["'none'"]}}}));
if (prod) app.set('trust proxy', 1);
app.use(express.json({limit:'220kb'}));
app.use(express.urlencoded({extended:false, limit:'10kb'}));
app.use(session({name:'clinic.sid', secret:sessionSecret, resave:false, saveUninitialized:false, cookie:{httpOnly:true, sameSite:'strict', secure:prod, maxAge:30*60*1000}}));
app.use('/api/', rateLimit({windowMs:15*60*1000, limit:300, standardHeaders:true, legacyHeaders:false}));
app.use('/api/login', rateLimit({windowMs:15*60*1000, limit:10, standardHeaders:true, legacyHeaders:false, message:{error:'تلاش‌های ورود بیش از حد است؛ بعداً دوباره امتحان کنید.'}}));

// Bootstrap an initial admin only on a new database. Change the credentials immediately.
if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0) {
  const username = safeText(process.env.ADMIN_USERNAME || 'admin', 80);
  const password = process.env.ADMIN_PASSWORD || 'ChangeThis-Immediately-2026!';
  if (password.length < 12) throw new Error('ADMIN_PASSWORD must be at least 12 characters.');
  db.prepare('INSERT INTO users(username,password_hash,display_name,role) VALUES(?,?,?,?)')
    .run(username, bcrypt.hashSync(password, 12), 'مدیر کلینیک', 'admin');
  console.warn('Initial admin created. Set ADMIN_USERNAME and ADMIN_PASSWORD securely; do not use demo credentials for real patient data.');
}

app.get('/api/session', (req,res) => res.json({user:req.session.user || null, modules:req.session.user ? roles[req.session.user.role] : []}));
app.post('/api/login', async (req,res) => {
  const username = safeText(req.body?.username,80), password = String(req.body?.password ?? '');
  const user = db.prepare('SELECT * FROM users WHERE username=? AND active=1').get(username);
  const ok = user ? await bcrypt.compare(password, user.password_hash) : await bcrypt.compare(password, '$2a$12$invalidhashinvalidhashinvalidhashinvalidhashinvalidhash');
  if (!user || !ok) { audit(req,'login_failed'); return res.status(401).json({error:'نام کاربری یا رمز عبور نادرست است.'}); }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({error:'خطا در ایجاد نشست کاربری.'});
    req.session.user = {id:user.id, username:user.username, name:user.display_name, role:user.role, avatarData:user.avatar_data || null};
    audit(req,'login'); res.json({user:req.session.user, modules:roles[user.role]});
  });
});
app.post('/api/logout', requireAuth, (req,res) => { audit(req,'logout'); req.session.destroy(()=>res.json({ok:true})); });
app.get('/api/modules', requireAuth, (req,res) => res.json(Object.fromEntries(Object.entries(modules).filter(([key])=>roles[req.session.user.role].includes(key)))));
app.get('/api/summary', requireAuth, allow('reports'), (req,res) => {
  const counts = {};
  for (const [key, def] of Object.entries(modules)) if (roles[req.session.user.role].includes(key)) counts[key] = db.prepare('SELECT COUNT(*) AS n FROM records WHERE module=?').get(key).n;
  let income = 0, expense = 0;
  if (roles[req.session.user.role].includes('finance')) {
    const rows = db.prepare("SELECT data FROM records WHERE module='finance'").all();
    for (const r of rows) { try { const d=JSON.parse(r.data); const amount=Number(d.amount||0); if(d.kind==='دریافت') income+=amount; if(d.kind==='هزینه') expense+=amount; } catch {} }
  }
  res.json({counts, income, expense, balance:income-expense});
});
app.get('/api/records/:module', requireAuth, (req,res) => {
  const m=req.params.module; if (!modules[m]) return res.status(404).json({error:'بخش پیدا نشد.'});
  if (!roles[req.session.user.role].includes(m)) return res.status(403).json({error:'دسترسی مجاز نیست.'});
  const rows=db.prepare('SELECT id,data,created_at,updated_at FROM records WHERE module=? ORDER BY id DESC LIMIT 500').all(m);
  res.json(rows.map(r=>({id:r.id,...JSON.parse(r.data),createdAt:r.created_at,updatedAt:r.updated_at})));
});
app.post('/api/records/:module', requireAuth, (req,res) => {
  const m=req.params.module; if (!modules[m]) return res.status(404).json({error:'بخش پیدا نشد.'});
  if (!roles[req.session.user.role].includes(m)) return res.status(403).json({error:'دسترسی مجاز نیست.'});
  const v=validateRecord(m,req.body); if(v.error) return res.status(400).json({error:v.error});
  const result=db.prepare('INSERT INTO records(module,data,created_by,updated_by) VALUES(?,?,?,?)').run(m,JSON.stringify(v.data),req.session.user.id,req.session.user.id);
  audit(req,'create',m,result.lastInsertRowid); res.status(201).json({id:result.lastInsertRowid,...v.data});
});
app.put('/api/records/:module/:id', requireAuth, (req,res) => {
  const m=req.params.module, id=Number(req.params.id); if (!modules[m] || !Number.isSafeInteger(id)) return res.status(400).json({error:'درخواست نامعتبر است.'});
  if (!roles[req.session.user.role].includes(m)) return res.status(403).json({error:'دسترسی مجاز نیست.'});
  const v=validateRecord(m,req.body); if(v.error) return res.status(400).json({error:v.error});
  const result=db.prepare('UPDATE records SET data=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND module=?').run(JSON.stringify(v.data),req.session.user.id,id,m);
  if(!result.changes) return res.status(404).json({error:'رکورد پیدا نشد.'});
  audit(req,'update',m,id); res.json({id,...v.data});
});
app.delete('/api/records/:module/:id', requireAuth, (req,res) => {
  if(req.session.user.role!=='admin') return res.status(403).json({error:'حذف رکورد فقط برای مدیر مجاز است.'});
  const m=req.params.module,id=Number(req.params.id); if(!modules[m]||!Number.isSafeInteger(id)) return res.status(400).json({error:'درخواست نامعتبر است.'});
  const result=db.prepare('DELETE FROM records WHERE id=? AND module=?').run(id,m); if(!result.changes) return res.status(404).json({error:'رکورد پیدا نشد.'});
  audit(req,'delete',m,id); res.json({ok:true});
});
app.get('/api/users', requireAuth, allow('users'), (req,res)=>res.json(db.prepare('SELECT id,username,display_name AS name,role,avatar_data AS avatarData,active,created_at AS createdAt FROM users ORDER BY id').all()));
app.post('/api/users', requireAuth, allow('users'), (req,res)=>{
  const username=safeText(req.body?.username,80), name=safeText(req.body?.name,120), password=String(req.body?.password||''), role=safeText(req.body?.role,20), avatarData=String(req.body?.avatarData||'');
  if(!/^[a-zA-Z0-9_.-]{3,80}$/.test(username)||name.length<2||password.length<12||!['admin','reception','doctor','finance','lab'].includes(role)) return res.status(400).json({error:'نام کاربری، نام، نقش یا رمز عبور معتبر نیست. رمز باید حداقل ۱۲ نویسه باشد.'});
  if (avatarData && (!/^data:image\/(jpeg|png|webp);base64,/.test(avatarData) || avatarData.length > 180000)) return res.status(400).json({error:'تصویر باید JPG، PNG یا WebP و کمتر از حدود ۱۳۰ کیلوبایت باشد.'});
  try { const result=db.prepare('INSERT INTO users(username,password_hash,display_name,role,avatar_data) VALUES(?,?,?,?,?)').run(username,bcrypt.hashSync(password,12),name,role,avatarData||null); audit(req,'create_user'); res.status(201).json({id:result.lastInsertRowid,username,name,role,avatarData:avatarData||null}); }
  catch { res.status(409).json({error:'این نام کاربری قبلاً ثبت شده است.'}); }
});
app.get('/api/reports/audit', requireAuth, allow('users'), (req,res)=>res.json(db.prepare('SELECT a.id,a.action,a.module,a.record_id AS recordId,a.ip,a.created_at AS createdAt,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 300').all()));
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{ console.error(err); res.status(500).json({error:'خطای داخلی رخ داد.'}); });
app.listen(PORT,()=>console.log(`Clinic Custom running at http://localhost:${PORT}`));
