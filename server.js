const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const url = require("url");

const PORT = process.env.PORT || 3000;
const ROOT = path.join(__dirname, "public");
const DB_PATH = path.join(__dirname, "db.json");

function readDB(){
  try { return JSON.parse(fs.readFileSync(DB_PATH, "utf8")); }
  catch(e){ return { users: [] }; }
}
function writeDB(db){
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}
function sha256(s){ return crypto.createHash("sha256").update(s, "utf8").digest("hex"); }

function json(res, code, obj){
  res.writeHead(code, { "Content-Type":"application/json; charset=utf-8", "Cache-Control":"no-store" });
  res.end(JSON.stringify(obj));
}
function parseBody(req){
  return new Promise((resolve)=>{
    let data="";
    req.on("data", c=> data += c);
    req.on("end", ()=>{ try{ resolve(JSON.parse(data||"{}")); } catch(e){ resolve({}); } });
  });
}
function parseCookies(req){
  const h = req.headers.cookie || "";
  const out = {};
  h.split(";").forEach(p=>{
    const i = p.indexOf("=");
    if(i>0) out[p.slice(0,i).trim()] = decodeURIComponent(p.slice(i+1).trim());
  });
  return out;
}
function setCookie(res, name, value, opts={}){
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if(opts.httpOnly) parts.push("HttpOnly");
  if(opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if(opts.path) parts.push(`Path=${opts.path}`);
  if(opts.maxAge!=null) parts.push(`Max-Age=${opts.maxAge}`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

const sessions = new Map(); // sid -> userId

function getUser(req){
  const sid = parseCookies(req).sid;
  if(!sid) return null;
  const uid = sessions.get(sid);
  if(!uid) return null;
  const db = readDB();
  return db.users.find(u=>u.id===uid) || null;
}

function mustAuth(req, res){
  const u = getUser(req);
  if(!u) { json(res, 401, { message:"Не авторизовано" }); return null; }
  if(u.banned) { json(res, 403, { message: u.banReason || "Вас було заблоковано Адміністраторами" }); return null; }
  return u;
}

function serveStatic(req, res, pathname){
  let filePath = path.join(ROOT, pathname);
  if(pathname==="/" || pathname==="") filePath = path.join(ROOT, "index.html");
  if(!filePath.startsWith(ROOT)){ res.writeHead(403); res.end("Forbidden"); return; }
  fs.readFile(filePath, (err, data)=>{
    if(err){ res.writeHead(404); res.end("Not found"); return; }
    const ext = path.extname(filePath).toLowerCase();
    const type = ({".html":"text/html; charset=utf-8",".js":"application/javascript; charset=utf-8",".css":"text/css; charset=utf-8",".svg":"image/svg+xml; charset=utf-8",".json":"application/json; charset=utf-8"}[ext] || "application/octet-stream");
    res.writeHead(200, { "Content-Type": type, "Cache-Control":"no-cache" });
    res.end(data);
  });
}
function makeId(prefix){ return prefix + crypto.randomBytes(6).toString("hex"); }

http.createServer(async (req, res)=>{
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || "/";

  if(pathname.startsWith("/api/")){
    if(pathname==="/api/me" && req.method==="GET"){
      const u = getUser(req);
      if(!u) return json(res, 401, { message:"Не авторизовано" });
      if(u.banned) return json(res, 403, { message: u.banReason || "Вас було заблоковано Адміністраторами" });
      return json(res, 200, { ok:true, user:{ id:u.id, name:u.name, role:u.role } });
    }

    if(pathname==="/api/login" && req.method==="POST"){
      const body = await parseBody(req);
      const key = (body.key||"").trim();
      if(!key) return json(res, 400, { message:"Введіть ключ" });
      const db = readDB();
      const h = sha256(key);
      const u = db.users.find(x=>x.keyHash===h);
      if(!u) return json(res, 401, { message:"Невірний ключ" });
      if(u.banned) return json(res, 403, { message: u.banReason || "Вас було заблоковано Адміністраторами" });

      const sid = crypto.randomBytes(24).toString("hex");
      sessions.set(sid, u.id);
      setCookie(res, "sid", sid, { httpOnly:true, sameSite:"Lax", path:"/" });
      return json(res, 200, { ok:true });
    }

    if(pathname==="/api/logout" && req.method==="POST"){
      const sid = parseCookies(req).sid;
      if(sid) sessions.delete(sid);
      setCookie(res, "sid", "", { httpOnly:true, sameSite:"Lax", path:"/", maxAge:0 });
      return json(res, 200, { ok:true });
    }

    if(pathname==="/api/users" && req.method==="GET"){
      const u = mustAuth(req, res); if(!u) return;
      if(u.role!=="owner") return json(res, 403, { message:"Тільки Власник" });
      const db = readDB();
      const list = db.users.map(x=>({ id:x.id, name:x.name, role:x.role, createdAt:x.createdAt||null, banned:!!x.banned }));
      return json(res, 200, { ok:true, users:list });
    }

    if(pathname==="/api/users" && req.method==="POST"){
      const u = mustAuth(req, res); if(!u) return;
      if(u.role!=="owner") return json(res, 403, { message:"Тільки Власник може створювати ключі" });

      const body = await parseBody(req);
      const name = (body.name||"user").toString().slice(0,60);
      const role = (body.role||"member").toString();
      if(!["owner","admin","member"].includes(role)) return json(res, 400, { message:"Невірна роль" });

      const keyPlain = "UA-" + crypto.randomBytes(10).toString("hex").toUpperCase();
      const id = makeId("u_");

      const db = readDB();
      db.users.push({ id, name, role, keyHash: sha256(keyPlain), createdAt: Date.now(), banned:false, banReason:"" });
      writeDB(db);
      return json(res, 200, { ok:true, key:keyPlain, id });
    }

    const mBan = pathname.match(/^\/api\/users\/([^\/]+)\/ban$/);
    if(mBan && req.method==="POST"){
      const u = mustAuth(req, res); if(!u) return;
      if(u.role!=="owner") return json(res, 403, { message:"Тільки Власник може банити/розбанювати" });

      const id = decodeURIComponent(mBan[1]);
      const body = await parseBody(req);
      const banned = !!body.banned;
      const reason = (body.reason||"").toString().slice(0,200);

      const db = readDB();
      const tgt = db.users.find(x=>x.id===id);
      if(!tgt) return json(res, 404, { message:"Не знайдено" });
      if(tgt.role==="owner") return json(res, 403, { message:"Не можна банити власника" });

      tgt.banned = banned;
      tgt.banReason = banned ? (reason || "Вас було заблоковано Адміністраторами") : "";
      writeDB(db);
      return json(res, 200, { ok:true });
    }

    return json(res, 404, { message:"Not found" });
  }

  serveStatic(req, res, pathname);
}).listen(PORT, ()=>console.log(`Server running on http://localhost:${PORT}`));
