const express=require('express');
const cors=require('cors');
const fs=require('fs');
const path=require('path');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const app=express(); app.use(cors()); app.use(express.json({limit:'5mb'}));
const PORT=process.env.PORT||8080; const SECRET=process.env.JWT_SECRET||'CHANGE_THIS_SECRET';
const FILE=path.join(__dirname,'data.json');
function load(){if(!fs.existsSync(FILE)){const adminPass=process.env.ADMIN_PASSWORD||'Admin123!';const d={users:[{id:1,name:'Адміністратор',email:process.env.ADMIN_EMAIL||'admin@demo.local',passwordHash:bcrypt.hashSync(adminPass,10),role:'admin'}],routes:[]};fs.writeFileSync(FILE,JSON.stringify(d,null,2));return d;}return JSON.parse(fs.readFileSync(FILE,'utf8'));}
function save(d){fs.writeFileSync(FILE,JSON.stringify(d,null,2));}
function auth(req,res,next){const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return res.status(401).json({error:'Потрібна авторизація'});try{req.user=jwt.verify(h.slice(7),SECRET);next();}catch(e){res.status(401).json({error:'Недійсний токен'});}}
function admin(req,res,next){if(req.user.role!=='admin')return res.status(403).json({error:'Потрібні права адміністратора'});next();}
app.get('/api/health',(req,res)=>res.json({ok:true}));
app.post('/api/register',(req,res)=>{const {name,email,password}=req.body||{};if(!name||!email||!password)return res.status(400).json({error:'Заповніть ім’я, e-mail і пароль'});const d=load();if(d.users.some(u=>u.email.toLowerCase()===email.toLowerCase()))return res.status(409).json({error:'Такий e-mail вже існує'});const u={id:Date.now(),name,email:email.toLowerCase(),passwordHash:bcrypt.hashSync(password,10),role:'courier'};d.users.push(u);save(d);const token=jwt.sign({id:u.id,email:u.email,role:u.role,name:u.name},SECRET,{expiresIn:'30d'});res.json({token,email:u.email,name:u.name,role:u.role});});
app.post('/api/login',(req,res)=>{const {email,password}=req.body||{};const d=load();const u=d.users.find(x=>x.email.toLowerCase()===String(email||'').toLowerCase());if(!u||!bcrypt.compareSync(String(password||''),u.passwordHash))return res.status(401).json({error:'Невірний e-mail або пароль'});const token=jwt.sign({id:u.id,email:u.email,role:u.role,name:u.name},SECRET,{expiresIn:'30d'});res.json({token,email:u.email,name:u.name,role:u.role});});
app.post('/api/sync',auth,(req,res)=>{const d=load();const incoming=Array.isArray(req.body.routes)?req.body.routes:[];const mine=incoming.filter(r=>r&&r.source==='Мої');const general=incoming.filter(r=>r&&r.source==='Загальний');for(const r of mine){r.ownerId=req.user.id;r.updatedAt=Date.now();const i=d.routes.findIndex(x=>x.id===r.id&&x.ownerId===req.user.id);if(i>=0)d.routes[i]=r;else d.routes.push(r);}if(req.user.role==='admin'){for(const r of general){r.ownerId=req.user.id;r.updatedAt=Date.now();const i=d.routes.findIndex(x=>x.id===r.id);if(i>=0)d.routes[i]=r;else d.routes.push(r);}}save(d);res.json({ok:true,savedMine:mine.length,savedGeneral:req.user.role==='admin'?general.length:0});});
app.get('/api/routes',auth,(req,res)=>{const d=load();const general=d.routes.filter(r=>r.source==='Загальний');const mine=d.routes.filter(r=>r.source==='Мої'&&r.ownerId===req.user.id);res.json({routes:[...general,...mine]});});
app.get('/api/admin/users',auth,admin,(req,res)=>{const d=load();res.json({users:d.users.map(u=>({id:u.id,name:u.name,email:u.email,role:u.role}))});});
app.get('/api/admin/routes',auth,admin,(req,res)=>{const d=load();res.json({routes:d.routes});});
app.delete('/api/admin/routes/:id',auth,admin,(req,res)=>{const d=load();const id=Number(req.params.id);const before=d.routes.length;d.routes=d.routes.filter(r=>Number(r.id)!==id);save(d);res.json({ok:true,deleted:before-d.routes.length});});
app.listen(PORT,()=>console.log(`API running on http://0.0.0.0:${PORT}/api`));
