const JSON_HEADERS = {"Content-Type":"application/json; charset=utf-8"};
const encoder = new TextEncoder();
const COOKIE = "bs_admin_session";
const SESSION_SECONDS = 8 * 60 * 60;

function json(data, status=200, headers={}) {
  return new Response(JSON.stringify(data), {status, headers:{...JSON_HEADERS,...headers}});
}
function normalize(value) {
  return String(value ?? "").normalize("NFKC").trim().toLocaleLowerCase("ar");
}
function safeEqual(a,b) {
  const x=encoder.encode(String(a)), y=encoder.encode(String(b));
  let diff=x.length ^ y.length, n=Math.max(x.length,y.length);
  for(let i=0;i<n;i++) diff |= (x[i]||0) ^ (y[i]||0);
  return diff===0;
}
async function digest(value) {
  const hash=await crypto.subtle.digest("SHA-256",encoder.encode(value));
  return [...new Uint8Array(hash)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function hmac(value, secret) {
  const key=await crypto.subtle.importKey("raw",encoder.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const sig=await crypto.subtle.sign("HMAC",key,encoder.encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function cookieValue(request,name) {
  const raw=request.headers.get("Cookie")||"";
  const part=raw.split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));
  return part ? decodeURIComponent(part.slice(name.length+1)) : "";
}
async function makeSession(env) {
  const payload=btoa(JSON.stringify({exp:Math.floor(Date.now()/1000)+SESSION_SECONDS,nonce:crypto.randomUUID()}));
  return `${payload}.${await hmac(payload,env.SESSION_SECRET)}`;
}
async function validSession(request,env) {
  const value=cookieValue(request,COOKIE), parts=value.split(".");
  if(parts.length!==2) return false;
  if(!safeEqual(parts[1],await hmac(parts[0],env.SESSION_SECRET))) return false;
  try { return JSON.parse(atob(parts[0])).exp > Math.floor(Date.now()/1000); } catch { return false; }
}
function corsHeaders(origin,env) {
  const allowed=[env.STUDENT_ORIGIN,env.ADMIN_ORIGIN].filter(Boolean);
  if(!origin || !allowed.includes(origin)) return {};
  return {"Access-Control-Allow-Origin":origin,"Access-Control-Allow-Credentials":"true","Access-Control-Allow-Methods":"GET,POST,PATCH,OPTIONS","Access-Control-Allow-Headers":"Content-Type,Authorization","Vary":"Origin"};
}
function validOrigin(request,env) {
  const origin=request.headers.get("Origin");
  return !!origin && [env.STUDENT_ORIGIN,env.ADMIN_ORIGIN].includes(origin);
}
async function body(request) {
  const len=Number(request.headers.get("Content-Length")||0);
  if(len>5000) throw new Error("حجم البيانات كبير");
  return await request.json();
}
function clean(value,max) {
  return String(value??"").normalize("NFKC").trim().replace(/\s+/g," ").slice(0,max);
}
async function rateLimit(env,ipHash) {
  const now=Date.now(), windowStart=now-15*60*1000;
  const row=await env.DB.prepare("SELECT COUNT(*) AS n FROM login_attempts WHERE ip_hash=? AND created_at>?").bind(ipHash,windowStart).first();
  return (row?.n||0) < 5;
}
async function recordFailure(env,ipHash) {
  await env.DB.prepare("INSERT INTO login_attempts(ip_hash,created_at) VALUES(?,?)").bind(ipHash,Date.now()).run();
}
async function handle(request,env) {
  const url=new URL(request.url), path=url.pathname, method=request.method;
  if(method==="OPTIONS") return new Response(null,{status:204,headers:corsHeaders(request.headers.get("Origin"),env)});
  if(path==="/api/health" && method==="GET") return json({status:"ok",service:"Belhrach School API"});
  if(path==="/api/student/requests" && method==="POST") {
    let data; try{data=await body(request)}catch{return json({error:"بيانات غير صالحة"},400)}
    const firstName=clean(data.firstName,60),lastName=clean(data.lastName,60),className=clean(data.className,40);
    if(!firstName||!lastName||!className) return json({error:"يرجى ملء جميع الحقول"},400);
    if(firstName.length<2||lastName.length<2) return json({error:"الاسم واللقب يجب أن يحتوي كل منهما على حرفين على الأقل"},400);
    const id=crypto.randomUUID(), token=crypto.randomUUID()+crypto.randomUUID(), tokenHash=await digest(token), createdAt=Date.now();
    await env.DB.prepare("INSERT INTO student_requests(id,first_name,last_name,class_name,status,token_hash,created_at) VALUES(?,?,?,?,?,?,?)").bind(id,firstName,lastName,className,"pending",tokenHash,createdAt).run();
    return json({ok:true,token,status:"pending"},201);
  }
  if(path==="/api/student/status" && method==="GET") {
    const token=(request.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
    if(token.length<50||token.length>150) return json({error:"رمز المتابعة غير صالح"},401);
    const row=await env.DB.prepare("SELECT status FROM student_requests WHERE token_hash=?").bind(await digest(token)).first();
    return row?json({status:row.status}):json({error:"الطلب غير موجود"},404);
  }
  if(path==="/api/admin/login" && method==="POST") {
    if(!validOrigin(request,env)) return json({error:"مصدر الطلب غير مسموح"},403);
    const ip=request.headers.get("CF-Connecting-IP")||"unknown", ipHash=await digest(ip+env.SESSION_SECRET);
    if(!await rateLimit(env,ipHash)) return json({error:"محاولات كثيرة. حاول بعد 15 دقيقة."},429);
    let data;try{data=await body(request)}catch{return json({error:"بيانات غير صالحة"},400)}
    const codeOk=safeEqual(String(data.code||""),env.ADMIN_ACCESS_CODE||"");
    const answerOk=safeEqual(normalize(data.answer),normalize(env.ADMIN_SECURITY_ANSWER||""));
    if(!codeOk||!answerOk){await recordFailure(env,ipHash);return json({error:"كود الإدارة أو إجابة سؤال التحقق غير صحيحة"},401)}
    await env.DB.prepare("DELETE FROM login_attempts WHERE ip_hash=?").bind(ipHash).run();
    const session=await makeSession(env);
    return json({ok:true},200,{"Set-Cookie":`${COOKIE}=${encodeURIComponent(session)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_SECONDS}`});
  }
  if(path==="/api/admin/logout" && method==="POST") {
    if(!validOrigin(request,env)||!await validSession(request,env)) return json({error:"غير مصرح"},401);
    return json({ok:true},200,{"Set-Cookie":`${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`});
  }
  if(path==="/api/admin/requests" && method==="GET") {
    if(!validOrigin(request,env)||!await validSession(request,env)) return json({error:"غير مصرح"},401);
    const result=await env.DB.prepare("SELECT id,first_name AS firstName,last_name AS lastName,class_name AS className,status,created_at AS createdAt FROM student_requests ORDER BY created_at DESC LIMIT 200").all();
    return json({requests:result.results||[]});
  }
  const match=path.match(/^\/api\/admin\/requests\/([0-9a-f-]{36})$/i);
  if(match && method==="PATCH") {
    if(!validOrigin(request,env)||!await validSession(request,env)) return json({error:"غير مصرح"},401);
    let data;try{data=await body(request)}catch{return json({error:"بيانات غير صالحة"},400)}
    if(!["approved","rejected"].includes(data.status)) return json({error:"قرار غير صالح"},400);
    const result=await env.DB.prepare("UPDATE student_requests SET status=? WHERE id=? AND status='pending'").bind(data.status,match[1]).run();
    if(!result.meta?.changes) return json({error:"الطلب غير موجود أو تمت معالجته سابقاً"},409);
    return json({ok:true,status:data.status});
  }
  return json({error:"المسار غير موجود"},404);
}
export default {
  async fetch(request,env) {
    const origin=request.headers.get("Origin");
    try {
      const response=await handle(request,env);
      const headers=new Headers(response.headers);
      for(const [k,v] of Object.entries(corsHeaders(origin,env))) headers.set(k,v);
      headers.set("X-Content-Type-Options","nosniff");
      headers.set("Referrer-Policy","no-referrer");
      headers.set("Cache-Control","no-store");
      return new Response(response.body,{status:response.status,headers});
    } catch(error) {
      return json({error:"خطأ داخلي في الخادم"},500,corsHeaders(origin,env));
    }
  }
};
