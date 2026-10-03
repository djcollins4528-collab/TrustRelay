import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import net from "node:net";
import tls from "node:tls";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT=path.dirname(fileURLToPath(import.meta.url));
const REAL_ROOT=fs.realpathSync(ROOT);
const PORT=Number(process.env.PORT||10000);
const SUPABASE_URL=String(process.env.SUPABASE_URL||"").replace(/\/$/,"");
const SUPABASE_PUBLISHABLE_KEY=String(process.env.SUPABASE_PUBLISHABLE_KEY||"");
const ENVIRONMENT=String(process.env.TRUSTRELAY_ENVIRONMENT||"staging");
const RENDER_GIT_COMMIT=String(process.env.RENDER_GIT_COMMIT||"").toLowerCase();
const APPROVED_COMMIT_SHA=String(process.env.TRUSTRELAY_APPROVED_COMMIT_SHA||"").toLowerCase();
const RUNTIME_DISABLED=/^(1|true|yes)$/i.test(String(process.env.TRUSTRELAY_RUNTIME_DISABLED||"false"));
const VERSION=String(process.env.TRUSTRELAY_APP_VERSION||"1.0.0");
const TURNSTILE_SITE_KEY=String(process.env.TRUSTRELAY_TURNSTILE_SITE_KEY||"");
const BODY_LIMIT=Math.max(1024,Number(process.env.TRUSTRELAY_BODY_LIMIT_BYTES||262144));
const REQUEST_TIMEOUT=Math.max(1000,Number(process.env.TRUSTRELAY_REQUEST_TIMEOUT_MS||8000));
const WEBHOOK_EGRESS_SECRET=String(process.env.TRUSTRELAY_WEBHOOK_EGRESS_SECRET||"");
const EDGE_ORIGIN_SECRET=String(process.env.TRUSTRELAY_EDGE_ORIGIN_SECRET||"");
const WEBHOOK_TARGET_TIMEOUT=Math.max(1000,Math.min(30000,Number(process.env.TRUSTRELAY_WEBHOOK_TARGET_TIMEOUT_MS||10000)));
const WEBHOOK_RESPONSE_LIMIT=Math.max(4096,Math.min(262144,Number(process.env.TRUSTRELAY_WEBHOOK_RESPONSE_LIMIT_BYTES||65536)));
const RATE_LIMIT_PER_MINUTE=Math.max(10,Math.min(5000,Number(process.env.TRUSTRELAY_RATE_LIMIT_PER_MINUTE||120)));
const RATE_LIMIT_WINDOW_MS=60_000;
const ALLOWED_HOSTS=new Set(String(process.env.TRUSTRELAY_ALLOWED_HOSTS||"").split(",").map(x=>x.trim().toLowerCase().replace(/\.$/,"")).filter(Boolean));
const rateBuckets=new Map();
let rateLimitSweepCounter=0;

if(!SUPABASE_URL||!SUPABASE_PUBLISHABLE_KEY){
  console.error("SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY are required");
  process.exit(1);
}

let supabaseUrlObject;
try{supabaseUrlObject=new URL(SUPABASE_URL)}
catch{
  console.error("SUPABASE_URL must be a valid URL");
  process.exit(1);
}
if(supabaseUrlObject.protocol!=="https:"){
  console.error("SUPABASE_URL must use HTTPS");
  process.exit(1);
}

const EXPECTED_PROD_SUPABASE_HOST="msfrbsnihylfynrtdgxe.supabase.co";
if(ENVIRONMENT==="production"){
  const failures=[];
  if(process.env.NODE_ENV!=="production")failures.push("NODE_ENV");
  if(process.env.RENDER!=="true")failures.push("RENDER_RUNTIME");
  if(String(process.env.RENDER_GIT_REPO_SLUG||"")!=="djcollins4528-collab/TrustRelay")failures.push("RENDER_GIT_REPO_SLUG");
  if(String(process.env.RENDER_GIT_BRANCH||"")!=="main")failures.push("RENDER_GIT_BRANCH");
  if(String(process.env.RENDER_SERVICE_ID||"")!=="srv-davrsuk9v7es738v9q7g")failures.push("RENDER_SERVICE_ID");
  if(String(process.env.RENDER_EXTERNAL_HOSTNAME||"")!=="trustrelay-production.onrender.com")failures.push("RENDER_EXTERNAL_HOSTNAME");
  if(!/^[0-9a-f]{40}$/.test(RENDER_GIT_COMMIT))failures.push("RENDER_GIT_COMMIT");
  if(!/^[0-9a-f]{40}$/.test(APPROVED_COMMIT_SHA))failures.push("TRUSTRELAY_APPROVED_COMMIT_SHA");
  if(RENDER_GIT_COMMIT!==APPROVED_COMMIT_SHA)failures.push("UNAPPROVED_COMMIT");
  if(!ALLOWED_HOSTS.size)failures.push("TRUSTRELAY_ALLOWED_HOSTS");
  if(!TURNSTILE_SITE_KEY)failures.push("TRUSTRELAY_TURNSTILE_SITE_KEY");
  if(supabaseUrlObject.hostname!==EXPECTED_PROD_SUPABASE_HOST)failures.push("SUPABASE_URL_PROJECT");
  if(EDGE_ORIGIN_SECRET&&EDGE_ORIGIN_SECRET.length<32)failures.push("TRUSTRELAY_EDGE_ORIGIN_SECRET_WEAK");
  if(failures.length){
    console.error("Production security configuration invalid:",failures.join(","));
    process.exit(1);
  }
}

const supabaseOrigin=supabaseUrlObject.origin;
const supabaseWs=supabaseOrigin.replace(/^https:/,"wss:");
const csp=[
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "script-src 'self' https://cdn.jsdelivr.net https://challenges.cloudflare.com",
  "script-src-attr 'none'",
  "media-src 'none'",
  "manifest-src 'self'",
  "worker-src 'self' blob:",
  "style-src 'self'",
  "style-src-attr 'none'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  `connect-src 'self' ${supabaseOrigin} ${supabaseWs} https://api.stripe.com https://checkout.stripe.com https://challenges.cloudflare.com`,
  "frame-src https://challenges.cloudflare.com",
  "form-action 'self' https://checkout.stripe.com",
  "upgrade-insecure-requests"
].join("; ");

const types={
  ".html":"text/html; charset=utf-8",".js":"text/javascript; charset=utf-8",
  ".mjs":"text/javascript; charset=utf-8",".css":"text/css; charset=utf-8",
  ".json":"application/json; charset=utf-8",".svg":"image/svg+xml",
  ".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".webp":"image/webp",
  ".ico":"image/x-icon",".txt":"text/plain; charset=utf-8"
};

const PUBLIC_TOP_LEVEL_FILES=new Set(["index.html"]);
const PUBLIC_DIRECTORIES=new Set(["web","verifier","reviewer","legal","pilot","support"]);
const PUBLIC_EXTENSIONS=new Set([".html",".js",".css",".json",".svg",".png",".jpg",".jpeg",".webp",".ico",".txt"]);


function headers(extra={}){
  return {
    "Content-Security-Policy":csp,
    "Strict-Transport-Security":"max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options":"nosniff",
    "X-Frame-Options":"DENY",
    "Referrer-Policy":"no-referrer",
    "Permissions-Policy":"accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), publickey-credentials-create=(self), publickey-credentials-get=(self), screen-wake-lock=(), usb=(), xr-spatial-tracking=()",
    "Cross-Origin-Opener-Policy":"same-origin",
    "Cross-Origin-Resource-Policy":"same-origin",
    "Origin-Agent-Cluster":"?1",
    "X-Permitted-Cross-Domain-Policies":"none",
    "X-DNS-Prefetch-Control":"off",
    "X-XSS-Protection":"0",
    ...extra
  };
}

function normalizedHost(req){
  const raw=String(req.headers.host||"").trim().toLowerCase();
  if(!raw||raw.length>255||/[\\s/@\\\\]/.test(raw))return "";
  if(raw.startsWith("["))return "";
  return raw.split(":")[0].replace(/\\.$/,"");
}
function hostAllowed(req){
  if(!ALLOWED_HOSTS.size)return true;
  return ALLOWED_HOSTS.has(normalizedHost(req));
}
function headerCount(req,name){
  const target=String(name).toLowerCase();
  let count=0;
  const raw=Array.isArray(req.rawHeaders)?req.rawHeaders:[];
  for(let i=0;i<raw.length;i+=2){
    if(String(raw[i]||"").toLowerCase()===target)count++;
  }
  return count;
}
function hasFramedBody(req){
  const length=String(req.headers["content-length"]||"").trim();
  return Boolean(req.headers["transfer-encoding"])||(length!==""&&Number(length)>0);
}
function looksLikeBrowserFetch(req){
  return ["sec-fetch-site","sec-fetch-mode","sec-fetch-dest","sec-fetch-user"].some(name=>req.headers[name]!==undefined)
    || Boolean(req.headers.origin);
}
function jsonContentType(req){
  const value=String(req.headers["content-type"]||"").toLowerCase();
  return value==="application/json"||value.startsWith("application/json;");
}

function sendJson(res,status,obj,extra={}){
  const body=JSON.stringify(obj);
  res.writeHead(status,headers({"Content-Type":"application/json; charset=utf-8","Content-Length":Buffer.byteLength(body),"Cache-Control":"no-store",...extra}));
  res.end(body);
}
function safeFile(urlPath){
  let decoded;
  try{decoded=decodeURIComponent(urlPath)}catch{return null}
  if(decoded.includes("\0")||decoded.includes("\\"))return null;
  let rel=decoded.replace(/^\/+/, "");
  if(!rel)rel="index.html";
  if(rel.endsWith("/"))rel+="index.html";

  const segments=rel.split("/").filter(Boolean);
  if(!segments.length||segments.some(part=>part==="."||part===".."||part.startsWith(".")))return null;

  const top=segments[0];
  const allowed=segments.length===1
    ? PUBLIC_TOP_LEVEL_FILES.has(rel)
    : PUBLIC_DIRECTORIES.has(top);
  if(!allowed)return null;

  const ext=path.extname(rel).toLowerCase();
  if(!PUBLIC_EXTENSIONS.has(ext)||ext===".map")return null;

  const candidate=path.resolve(ROOT,rel);
  if(candidate!==ROOT&&!candidate.startsWith(ROOT+path.sep))return null;
  let real;
  try{real=fs.realpathSync(candidate)}catch{return null}
  if(real!==REAL_ROOT&&!real.startsWith(REAL_ROOT+path.sep))return null;
  return real;
}
async function readBody(req,limit=BODY_LIMIT){
  const chunks=[];let size=0;
  for await(const chunk of req){
    size+=chunk.length;
    if(size>limit)throw Object.assign(new Error("BODY_TOO_LARGE"),{status:413});
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
async function proxyPartner(req,res,url){
  const suffix=url.pathname.replace(/^\/v1\//,"/v1/");
  const target=SUPABASE_URL+"/functions/v1/trustrelay-partner-v07"+suffix+url.search;
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),REQUEST_TIMEOUT);
  try{
    const h={"apikey":SUPABASE_PUBLISHABLE_KEY,"accept":req.headers.accept||"application/json"};
    if(req.headers["content-type"])h["content-type"]=req.headers["content-type"];
    if(req.headers["x-trustrelay-key"])h["x-trustrelay-key"]=req.headers["x-trustrelay-key"];
    if(req.headers.authorization)h.authorization=req.headers.authorization;
    const init={method:req.method,headers:h,signal:controller.signal};
    if(!["GET","HEAD"].includes(req.method||"GET"))init.body=await readBody(req);
    const upstream=await fetch(target,init);
    const body=Buffer.from(await upstream.arrayBuffer());
    res.writeHead(upstream.status,headers({
      "Content-Type":upstream.headers.get("content-type")||"application/json; charset=utf-8",
      "Content-Length":body.length,
      "Cache-Control":"no-store"
    }));
    res.end(body);
  }catch(e){
    sendJson(res,e?.status||503,{error:{code:e?.name==="AbortError"?"UPSTREAM_TIMEOUT":e?.message==="BODY_TOO_LARGE"?"BODY_TOO_LARGE":"UPSTREAM_UNAVAILABLE"}});
  }finally{clearTimeout(timer)}
}


function secretEqual(a,b){
  if(!a||!b)return false;
  const aa=Buffer.from(String(a));const bb=Buffer.from(String(b));
  return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb);
}
function ipv4Number(ip){
  const p=ip.split(".").map(Number);
  if(p.length!==4||p.some(x=>!Number.isInteger(x)||x<0||x>255))return null;
  return (((p[0]<<24)>>>0)+(p[1]<<16)+(p[2]<<8)+p[3])>>>0;
}
function inV4(ip,base,bits){
  const x=ipv4Number(ip),b=ipv4Number(base);if(x===null||b===null)return true;
  const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;
  return (x&mask)===(b&mask);
}
function isPublicIpv4(ip){
  const blocked=[
    ["0.0.0.0",8],["10.0.0.0",8],["100.64.0.0",10],["127.0.0.0",8],
    ["169.254.0.0",16],["172.16.0.0",12],["192.0.0.0",24],["192.0.2.0",24],
    ["192.88.99.0",24],["192.168.0.0",16],["198.18.0.0",15],["198.51.100.0",24],
    ["203.0.113.0",24],["224.0.0.0",4],["240.0.0.0",4]
  ];
  return !blocked.some(([base,bits])=>inV4(ip,base,bits));
}
function isPublicIpv6(ip){
  const x=ip.toLowerCase().split("%")[0];
  const firstText=x.split(":")[0];
  const first=Number.parseInt(firstText,16);
  if(!Number.isFinite(first)||first<0x2000||first>0x3fff)return false;
  if(/^2001:(?:0{0,3}0)(?::|$)/.test(x))return false; // Teredo
  if(/^2001:(?:0{0,3}2)(?::|$)/.test(x))return false; // benchmarking
  if(/^2001:(?:0{0,3}1[0-9a-f])(?::|$)/.test(x))return false; // ORCHID/reserved
  if(/^2001:db8(?::|$)/.test(x))return false; // documentation
  if(/^2002(?::|$)/.test(x))return false; // 6to4
  return true;
}
function isPublicAddress(ip){
  const kind=net.isIP(ip);
  if(kind===4)return isPublicIpv4(ip);
  if(kind===6)return isPublicIpv6(ip);
  return false;
}
async function resolvePinnedTarget(hostname){
  const raw=hostname.replace(/^\[/,"").replace(/\]$/,"").replace(/\.$/,"").toLowerCase();
  if(!raw||raw==="localhost"||raw.endsWith(".localhost")||raw.endsWith(".local")||raw.endsWith(".internal")){
    throw Object.assign(new Error("WEBHOOK_PRIVATE_TARGET"),{status:403});
  }
  if(net.isIP(raw)){
    if(!isPublicAddress(raw))throw Object.assign(new Error("WEBHOOK_PRIVATE_TARGET"),{status:403});
    return raw;
  }
  let answers;
  try{answers=await dns.promises.lookup(raw,{all:true,verbatim:true})}
  catch{throw Object.assign(new Error("WEBHOOK_DNS_RESOLUTION_FAILED"),{status:502})}
  const addresses=[...new Set((answers||[]).map(x=>x.address).filter(Boolean))];
  if(!addresses.length)throw Object.assign(new Error("WEBHOOK_DNS_RESOLUTION_FAILED"),{status:502});
  if(addresses.some(ip=>!isPublicAddress(ip))){
    throw Object.assign(new Error("WEBHOOK_PRIVATE_TARGET"),{status:403});
  }
  return addresses[0];
}
function webhookHeaders(input,hostHeader,body){
  const allowed=new Map([
    ["content-type","Content-Type"],["user-agent","User-Agent"],
    ["x-trustrelay-event","X-TrustRelay-Event"],["x-trustrelay-delivery","X-TrustRelay-Delivery"],
    ["x-trustrelay-timestamp","X-TrustRelay-Timestamp"],["x-trustrelay-signature","X-TrustRelay-Signature"]
  ]);
  const out={Host:hostHeader,"Content-Length":Buffer.byteLength(body)};
  for(const [k,v] of Object.entries(input||{})){
    const target=allowed.get(k.toLowerCase());
    if(target&&typeof v==="string"&&v.length<=2048)out[target]=v;
  }
  if(!out["Content-Type"])out["Content-Type"]="application/json";
  return out;
}
async function deliverPinnedWebhook(endpoint,body,inputHeaders){
  let u;
  try{u=new URL(endpoint)}catch{throw Object.assign(new Error("WEBHOOK_URL_INVALID"),{status:400})}
  if(u.protocol!=="https:"||u.username||u.password||!u.hostname){
    throw Object.assign(new Error("WEBHOOK_URL_INVALID"),{status:400});
  }
  if(u.port&&u.port!=="443")throw Object.assign(new Error("WEBHOOK_PORT_FORBIDDEN"),{status:400});
  if((u.pathname+u.search).length>8192)throw Object.assign(new Error("WEBHOOK_URL_INVALID"),{status:400});
  const originalHost=u.hostname.replace(/^\[/,"").replace(/\]$/,"").replace(/\.$/,"");
  const pinned=await resolvePinnedTarget(originalHost);
  const requestHeaders=webhookHeaders(inputHeaders,u.host,body);
  return await new Promise((resolve,reject)=>{
    const out=https.request({
      protocol:"https:",hostname:pinned,port:443,method:"POST",path:u.pathname+u.search,
      servername:originalHost,rejectUnauthorized:true,
      checkServerIdentity:(_host,cert)=>tls.checkServerIdentity(originalHost,cert),
      headers:requestHeaders
    },up=>{
      const chunks=[];let size=0;
      up.on("data",chunk=>{
        size+=chunk.length;
        if(size>WEBHOOK_RESPONSE_LIMIT){
          up.destroy(Object.assign(new Error("WEBHOOK_RESPONSE_TOO_LARGE"),{status:502}));
          return;
        }
        chunks.push(chunk);
      });
      up.on("end",()=>resolve({
        status:up.statusCode||502,
        contentType:up.headers["content-type"]||"application/octet-stream",
        body:Buffer.concat(chunks)
      }));
    });
    out.setTimeout(WEBHOOK_TARGET_TIMEOUT,()=>out.destroy(Object.assign(new Error("WEBHOOK_TARGET_TIMEOUT"),{status:504})));
    out.on("error",reject);
    out.end(body);
  });
}
function clientIp(req){
  // Render documents X-Forwarded-For as the source of the real client IP.
  // Prefer it over Cloudflare-specific headers so callers cannot influence
  // the limiter key with an injected CF-Connecting-IP value.
  const forwarded=String(req.headers["x-forwarded-for"]||"");
  if(forwarded){
    const first=forwarded.split(",")[0].trim().replace(/^\[|\]$/g,"");
    if(net.isIP(first))return first;
  }
  const cf=String(req.headers["cf-connecting-ip"]||"").trim();
  if(net.isIP(cf))return cf;
  const remote=String(req.socket?.remoteAddress||"unknown").replace(/^::ffff:/,"");
  return remote||"unknown";
}
function consumeRuntimeRateLimit(req){
  const now=Date.now();
  const key=clientIp(req);
  let bucket=rateBuckets.get(key);
  if(!bucket||now-bucket.startedAt>=RATE_LIMIT_WINDOW_MS){
    bucket={startedAt:now,count:0};
    rateBuckets.set(key,bucket);
  }
  bucket.count++;
  if(++rateLimitSweepCounter%500===0){
    for(const [k,v] of rateBuckets){
      if(now-v.startedAt>=RATE_LIMIT_WINDOW_MS*2)rateBuckets.delete(k);
    }
  }
  const remaining=Math.max(0,RATE_LIMIT_PER_MINUTE-bucket.count);
  const resetSeconds=Math.max(1,Math.ceil((bucket.startedAt+RATE_LIMIT_WINDOW_MS-now)/1000));
  return {allowed:bucket.count<=RATE_LIMIT_PER_MINUTE,remaining,resetSeconds};
}
function isRateLimitedPath(pathname){
  return pathname==="/runtime-config.json"||pathname==="/version"||pathname.startsWith("/v1/")||pathname.startsWith("/internal/");
}
function applyRuntimeRateLimit(req,res,pathname){
  if(!isRateLimitedPath(pathname))return true;
  const r=consumeRuntimeRateLimit(req);
  if(r.allowed)return true;
  sendJson(res,429,{error:{code:"RATE_LIMITED"}},{
    "Retry-After":String(r.resetSeconds),
    "RateLimit-Limit":String(RATE_LIMIT_PER_MINUTE),
    "RateLimit-Remaining":"0",
    "RateLimit-Reset":String(r.resetSeconds)
  });
  return false;
}

async function proxyWebhookEgress(req,res){
  if(!WEBHOOK_EGRESS_SECRET)return sendJson(res,503,{error:{code:"WEBHOOK_EGRESS_NOT_CONFIGURED"}});
  const auth=String(req.headers.authorization||"");
  const token=auth.startsWith("Bearer ")?auth.slice(7):"";
  if(!secretEqual(token,WEBHOOK_EGRESS_SECRET))return sendJson(res,401,{error:{code:"WEBHOOK_EGRESS_UNAUTHORIZED"}});
  if(req.method!=="POST")return sendJson(res,405,{error:{code:"METHOD_NOT_ALLOWED"}},{Allow:"POST"});
  try{
    const raw=await readBody(req,BODY_LIMIT+65536);
    let input;try{input=JSON.parse(raw.toString("utf8"))}catch{throw Object.assign(new Error("WEBHOOK_RELAY_PAYLOAD_INVALID"),{status:400})}
    if(typeof input?.endpointUrl!=="string"||typeof input?.body!=="string"||input.body.length>BODY_LIMIT){
      throw Object.assign(new Error("WEBHOOK_RELAY_PAYLOAD_INVALID"),{status:400});
    }
    const delivered=await deliverPinnedWebhook(input.endpointUrl,input.body,input.headers||{});
    res.writeHead(delivered.status,headers({
      "Content-Type":delivered.contentType,
      "Content-Length":delivered.body.length,
      "Cache-Control":"no-store"
    }));
    res.end(delivered.body);
  }catch(e){
    const code=String(e?.message||"WEBHOOK_EGRESS_FAILED");
    const status=Number(e?.status)||502;
    console.warn("webhook-egress",code);
    return sendJson(res,status,{error:{code}});
  }
}

const server=http.createServer({
  maxHeaderSize:8192,
  requireHostHeader:true,
  insecureHTTPParser:false,
  joinDuplicateHeaders:false
},async(req,res)=>{
  const method=String(req.method||"GET").toUpperCase();
  const rawTarget=String(req.url||"");
  if(method==="TRACE"||method==="CONNECT")return sendJson(res,405,{error:{code:"METHOD_NOT_ALLOWED"}},{Allow:"GET, HEAD, POST"});
  if(!rawTarget.startsWith("/")||rawTarget.startsWith("//"))return sendJson(res,400,{error:{code:"INVALID_REQUEST_TARGET"}});
  if(req.headers["transfer-encoding"]&&req.headers["content-length"])return sendJson(res,400,{error:{code:"AMBIGUOUS_REQUEST_BODY"}});
  for(const critical of ["host","authorization","x-trustrelay-key","content-length","transfer-encoding"]){
    if(headerCount(req,critical)>1)return sendJson(res,400,{error:{code:"DUPLICATE_CRITICAL_HEADER"}});
  }
  if((method==="GET"||method==="HEAD")&&hasFramedBody(req))return sendJson(res,400,{error:{code:"UNEXPECTED_REQUEST_BODY"}});
  if(rawTarget.length>8192)return sendJson(res,414,{error:{code:"URI_TOO_LONG"}});
  let url;
  try{url=new URL(req.url||"/","http://localhost")}
  catch{return sendJson(res,400,{error:{code:"INVALID_URL"}})}
  if(url.pathname==="/healthz"){
    if(!["GET","HEAD"].includes(req.method||"GET"))return sendJson(res,405,{error:{code:"METHOD_NOT_ALLOWED"}},{Allow:"GET, HEAD"});
    return sendJson(res,200,{status:RUNTIME_DISABLED?"quarantined":"ok"});
  }
  if(!hostAllowed(req))return sendJson(res,421,{error:{code:"HOST_NOT_ALLOWED"}});
  if(EDGE_ORIGIN_SECRET&&!secretEqual(String(req.headers["x-trustrelay-edge-origin"]||""),EDGE_ORIGIN_SECRET)){
    return sendJson(res,403,{error:{code:"EDGE_ORIGIN_REQUIRED"}});
  }
  if(RUNTIME_DISABLED){
    return sendJson(res,503,{error:{code:"RUNTIME_QUARANTINED"}},{"Retry-After":"3600"});
  }
  if(!applyRuntimeRateLimit(req,res,url.pathname))return;
  if(url.pathname==="/internal/webhook-egress"){
    return sendJson(res,410,{error:{code:"WEBHOOK_EGRESS_RETIRED",replacement:"trustrelay-webhook-egress-v10"}});
  }
  if(ENVIRONMENT==="production"&&(url.pathname==="/reviewer"||url.pathname.startsWith("/reviewer/"))){
    return sendJson(res,404,{error:{code:"NOT_FOUND"}});
  }
  if(url.pathname==="/version"){
    if(!["GET","HEAD"].includes(req.method||"GET"))return sendJson(res,405,{error:{code:"METHOD_NOT_ALLOWED"}},{Allow:"GET, HEAD"});
    if(ENVIRONMENT==="production")return sendJson(res,404,{error:{code:"NOT_FOUND"}});
    return sendJson(res,200,{version:VERSION,environment:ENVIRONMENT});
  }
  if(url.pathname==="/runtime-config.json"){
    if(!["GET","HEAD"].includes(req.method||"GET"))return sendJson(res,405,{error:{code:"METHOD_NOT_ALLOWED"}},{Allow:"GET, HEAD"});
    return sendJson(res,200,{
      supabaseUrl:SUPABASE_URL,
      supabasePublishableKey:SUPABASE_PUBLISHABLE_KEY,
      environment:ENVIRONMENT,
      appVersion:VERSION,
      turnstileSiteKey:TURNSTILE_SITE_KEY
    });
  }
  if(url.pathname.startsWith("/v1/decisions/")){
    if(looksLikeBrowserFetch(req))return sendJson(res,403,{error:{code:"BROWSER_PARTNER_API_FORBIDDEN"}});
    if(!["GET","HEAD"].includes(method)&&!jsonContentType(req))return sendJson(res,415,{error:{code:"JSON_CONTENT_TYPE_REQUIRED"}});
    return proxyPartner(req,res,url);
  }
  if(!["GET","HEAD"].includes(req.method||"GET")){
    return sendJson(res,405,{error:{code:"METHOD_NOT_ALLOWED"}},{Allow:"GET, HEAD"});
  }

  const file=safeFile(url.pathname);
  if(!file)return sendJson(res,404,{error:{code:"NOT_FOUND"}});
  let st;
  try{st=fs.statSync(file)}catch{return sendJson(res,404,{error:{code:"NOT_FOUND"}})}
  let actual=file;
  if(st.isDirectory())actual=path.join(file,"index.html");
  try{
    const data=fs.readFileSync(actual);
    const ext=path.extname(actual).toLowerCase();
    const html=ext===".html";
    const relative=path.relative(ROOT,actual).split(path.sep).join("/");
    const securitySensitive=html||/^(web|verifier|reviewer)\//.test(relative);
    res.writeHead(200,headers({
      "Content-Type":types[ext]||"application/octet-stream",
      "Content-Length":data.length,
      "Cache-Control":securitySensitive?"no-store":"public, max-age=300",
      ...(securitySensitive?{"Pragma":"no-cache","Expires":"0","X-Robots-Tag":"noindex, nofollow, noarchive"}:{})
    }));
    if(req.method==="HEAD")res.end();else res.end(data);
  }catch{
    sendJson(res,404,{error:{code:"NOT_FOUND"}});
  }
});

server.requestTimeout=15000;
server.headersTimeout=10000;
server.keepAliveTimeout=5000;
server.maxHeadersCount=64;
server.maxRequestsPerSocket=50;
server.on("clientError",(err,socket)=>{
  if(!socket.writable)return;
  const code=err?.code==="HPE_HEADER_OVERFLOW"?"431 Request Header Fields Too Large":"400 Bad Request";
  socket.end(`HTTP/1.1 ${code}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
});

server.listen(PORT,"0.0.0.0",()=>console.log(`TrustRelay ${VERSION} (${ENVIRONMENT}) listening on ${PORT}`));
