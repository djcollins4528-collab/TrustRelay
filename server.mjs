import http from "node:http";
import net from "node:net";
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
const EDGE_ORIGIN_SECRET=String(process.env.TRUSTRELAY_EDGE_ORIGIN_SECRET||"");
const REQUIRE_EDGE_ORIGIN=/^(1|true|yes)$/i.test(String(process.env.TRUSTRELAY_REQUIRE_EDGE_ORIGIN||"false"));
const PARTNER_RESPONSE_LIMIT=Math.max(4096,Math.min(4*1024*1024,Number(process.env.TRUSTRELAY_PARTNER_RESPONSE_LIMIT_BYTES||1048576)));
const RATE_LIMIT_PER_MINUTE=Math.max(10,Math.min(5000,Number(process.env.TRUSTRELAY_RATE_LIMIT_PER_MINUTE||120)));
const RATE_LIMIT_WINDOW_MS=60_000;
const ALLOWED_HOSTS=new Set(String(process.env.TRUSTRELAY_ALLOWED_HOSTS||"").split(",").map(x=>x.trim().toLowerCase().replace(/\.$/,"")).filter(Boolean));
const RENDER_EXTERNAL_HOSTNAME=String(process.env.RENDER_EXTERNAL_HOSTNAME||"").trim().toLowerCase().replace(/\.$/,"");
// Before the Cloudflare edge-origin cutover, Render's canonical public hostname
// must remain reachable. Strict edge mode intentionally stops auto-trusting it.
if(RENDER_EXTERNAL_HOSTNAME&&(ENVIRONMENT!=="production"||!REQUIRE_EDGE_ORIGIN))ALLOWED_HOSTS.add(RENDER_EXTERNAL_HOSTNAME);
if(ENVIRONMENT!=="production")ALLOWED_HOSTS.add("trustrelay-staging.onrender.com");
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
  if(REQUIRE_EDGE_ORIGIN&&!EDGE_ORIGIN_SECRET)failures.push("TRUSTRELAY_EDGE_ORIGIN_SECRET_REQUIRED");
  if(EDGE_ORIGIN_SECRET&&EDGE_ORIGIN_SECRET.length<32)failures.push("TRUSTRELAY_EDGE_ORIGIN_SECRET_WEAK");
  if(REQUIRE_EDGE_ORIGIN&&[...ALLOWED_HOSTS].some(host=>host.endsWith(".onrender.com")))failures.push("TRUSTRELAY_EDGE_ORIGIN_PUBLIC_RENDER_HOST");
  if(failures.length){
    console.error("Production security configuration invalid:",failures.join(","));
    process.exit(1);
  }
}

const supabaseOrigin=supabaseUrlObject.origin;
const supabaseWs=supabaseOrigin.replace(/^https:/,"wss:");
const csp=[
  "default-src 'none'",
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
const PUBLIC_DIRECTORIES=new Set(["web","verifier","reviewer","legal","pilot","support","developers"]);
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
    "Cross-Origin-Embedder-Policy":"credentialless",
    "Origin-Agent-Cluster":"?1",
    "X-Permitted-Cross-Domain-Policies":"none",
    "X-DNS-Prefetch-Control":"off",
    "X-XSS-Protection":"0",
    ...extra
  };
}

function normalizedHost(req){
  const raw=String(req.headers.host||"").trim().toLowerCase();
  if(!raw||raw.length>255||/[\s/@\\]/.test(raw))return "";
  if(raw.startsWith("["))return "";
  return raw.split(":")[0].replace(/\\.$/,"");
}
function trustedStagingRenderIdentity(){
  return ENVIRONMENT==="staging"
    && String(process.env.RENDER_SERVICE_ID||"")==="srv-davrss2d0e5s7395aq10"
    && RENDER_EXTERNAL_HOSTNAME==="trustrelay-staging.onrender.com"
    && String(process.env.RENDER_GIT_REPO_SLUG||"")==="djcollins4528-collab/TrustRelay"
    && String(process.env.RENDER_GIT_BRANCH||"")==="main";
}
function hostAllowed(req){
  const host=normalizedHost(req);
  if(host)return !ALLOWED_HOSTS.size||ALLOWED_HOSTS.has(host);
  if(trustedStagingRenderIdentity())return ALLOWED_HOSTS.has(RENDER_EXTERNAL_HOSTNAME);
  if(ENVIRONMENT!=="production"||String(process.env.RENDER||"")!=="true")return false;
  if(!REQUIRE_EDGE_ORIGIN||!EDGE_ORIGIN_SECRET)return false;
  return secretEqual(String(req.headers["x-trustrelay-edge-origin"]||""),EDGE_ORIGIN_SECRET);
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
async function readLimitedResponse(response,limit=PARTNER_RESPONSE_LIMIT){
  const declared=Number(response.headers.get("content-length")||0);
  if(Number.isFinite(declared)&&declared>limit){
    throw Object.assign(new Error("UPSTREAM_RESPONSE_TOO_LARGE"),{status:502});
  }
  if(!response.body)return Buffer.alloc(0);
  const chunks=[];let size=0;
  for await(const chunk of response.body){
    const buf=Buffer.from(chunk);
    size+=buf.length;
    if(size>limit){
      try{await response.body.cancel()}catch{}
      throw Object.assign(new Error("UPSTREAM_RESPONSE_TOO_LARGE"),{status:502});
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks,size);
}
async function proxyPartner(req,res,url){
  const suffix=url.pathname.replace(/^\/v1\//,"/v1/");
  const target=SUPABASE_URL+"/functions/v1/trustrelay-partner-v07"+suffix+url.search;
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),REQUEST_TIMEOUT);
  try{
    const h={"apikey":SUPABASE_PUBLISHABLE_KEY,"accept":"application/json"};
    if(req.headers["content-type"])h["content-type"]=req.headers["content-type"];
    if(req.headers["x-trustrelay-key"])h["x-trustrelay-key"]=req.headers["x-trustrelay-key"];
    if(req.headers.authorization)h.authorization=req.headers.authorization;
    const init={method:req.method,headers:h,signal:controller.signal};
    if(!["GET","HEAD"].includes(req.method||"GET"))init.body=await readBody(req);
    const upstream=await fetch(target,init);
    const body=await readLimitedResponse(upstream);
    const upstreamType=String(upstream.headers.get("content-type")||"application/json; charset=utf-8");
    const safeType=/^application\/(?:json|problem\+json)(?:\s*;|$)/i.test(upstreamType)
      ? upstreamType
      : "application/octet-stream";
    res.writeHead(upstream.status,headers({
      "Content-Type":safeType,
      "Content-Length":body.length,
      "Cache-Control":"no-store"
    }));
    res.end(body);
  }catch(e){
    const code=e?.name==="AbortError"
      ?"UPSTREAM_TIMEOUT"
      :e?.message==="BODY_TOO_LARGE"
        ?"BODY_TOO_LARGE"
        :e?.message==="UPSTREAM_RESPONSE_TOO_LARGE"
          ?"UPSTREAM_RESPONSE_TOO_LARGE"
          :"UPSTREAM_UNAVAILABLE";
    sendJson(res,e?.status||503,{error:{code}});
  }finally{clearTimeout(timer)}
}



async function proxyScim(req,res,url){
  const suffix=url.pathname.replace(/^\/scim\/v2\/?/,"/");
  const target=SUPABASE_URL+"/functions/v1/trustrelay-scim-v14"+suffix+url.search;
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),REQUEST_TIMEOUT);
  try{
    const h={"apikey":SUPABASE_PUBLISHABLE_KEY,"accept":"application/scim+json, application/json"};
    if(req.headers["content-type"])h["content-type"]=req.headers["content-type"];
    if(req.headers.authorization)h.authorization=req.headers.authorization;
    const init={method:req.method,headers:h,signal:controller.signal};
    if(!["GET","HEAD"].includes(req.method||"GET"))init.body=await readBody(req);
    const upstream=await fetch(target,init);
    const body=await readLimitedResponse(upstream);
    const upstreamType=String(upstream.headers.get("content-type")||"application/scim+json; charset=utf-8");
    const safeType=/^application\/(?:scim\+json|json|problem\+json)(?:\s*;|$)/i.test(upstreamType)
      ? upstreamType
      : "application/octet-stream";
    const extra={
      "Content-Type":safeType,
      "Content-Length":body.length,
      "Cache-Control":"no-store"
    };
    const location=upstream.headers.get("location");
    if(location)extra.Location=location;
    res.writeHead(upstream.status,headers(extra));
    res.end(body);
  }catch(e){
    const code=e?.name==="AbortError"
      ?"UPSTREAM_TIMEOUT"
      :e?.message==="BODY_TOO_LARGE"
        ?"BODY_TOO_LARGE"
        :e?.message==="UPSTREAM_RESPONSE_TOO_LARGE"
          ?"UPSTREAM_RESPONSE_TOO_LARGE"
          :"UPSTREAM_UNAVAILABLE";
    sendJson(res,e?.status||503,{error:{code}});
  }finally{clearTimeout(timer)}
}

function secretEqual(a,b){
  if(!a||!b)return false;
  const aa=Buffer.from(String(a));const bb=Buffer.from(String(b));
  return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb);
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
  return pathname==="/runtime-config.json"||pathname==="/version"||pathname.startsWith("/v1/")||pathname.startsWith("/scim/v2")||pathname.startsWith("/internal/");
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
  for(const critical of ["host","authorization","x-trustrelay-key","x-trustrelay-edge-origin","content-length","transfer-encoding"]){
    if(headerCount(req,critical)>1)return sendJson(res,400,{error:{code:"DUPLICATE_CRITICAL_HEADER"}});
  }
  if((method==="GET"||method==="HEAD")&&hasFramedBody(req))return sendJson(res,400,{error:{code:"UNEXPECTED_REQUEST_BODY"}});
  if(rawTarget.length>8192)return sendJson(res,414,{error:{code:"URI_TOO_LONG"}});
  let url;
  try{url=new URL(req.url||"/","http://localhost")}
  catch{return sendJson(res,400,{error:{code:"INVALID_URL"}})}
  if(url.pathname==="/healthz"){
    if(!["GET","HEAD"].includes(req.method||"GET"))return sendJson(res,405,{error:{code:"METHOD_NOT_ALLOWED"}},{Allow:"GET, HEAD"});
    return sendJson(res,200,{status:RUNTIME_DISABLED?"quarantined":"ok"},{"Cache-Control":"no-cache, no-store, must-revalidate, max-age=0, private","Pragma":"no-cache","Expires":"0"});
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
    return sendJson(res,200,{version:VERSION,environment:ENVIRONMENT,commit:RENDER_GIT_COMMIT||null});
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
  if(url.pathname==="/scim/v2"||url.pathname.startsWith("/scim/v2/")){
    if(looksLikeBrowserFetch(req))return sendJson(res,403,{error:{code:"BROWSER_SCIM_FORBIDDEN"}});
    if(!["GET","POST","PUT","PATCH","DELETE"].includes(method)){
      return sendJson(res,405,{error:{code:"METHOD_NOT_ALLOWED"}},{Allow:"GET, POST, PUT, PATCH, DELETE"});
    }
    if(["POST","PUT","PATCH"].includes(method)){
      const ct=String(req.headers["content-type"]||"").toLowerCase();
      if(!ct.startsWith("application/scim+json")&&!ct.startsWith("application/json")){
        return sendJson(res,415,{error:{code:"SCIM_CONTENT_TYPE_REQUIRED"}});
      }
    }
    return proxyScim(req,res,url);
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
    const authenticatedSurface=/^(web|verifier|reviewer)\//.test(relative);
    const noStore=html||authenticatedSurface;
    res.writeHead(200,headers({
      "Content-Type":types[ext]||"application/octet-stream",
      "Content-Length":data.length,
      "Cache-Control":noStore?"no-cache, no-store, must-revalidate, max-age=0":"public, max-age=300, immutable",
      ...(noStore?{"Pragma":"no-cache","Expires":"0"}:{}),
      ...(authenticatedSurface?{"X-Robots-Tag":"noindex, nofollow, noarchive"}:{})
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

async function runStagingScimE2E(){
  if(ENVIRONMENT!=="staging"||process.env.SCIM_E2E_ON_STARTUP!=="1")return;
  const base=String(process.env.SCIM_E2E_BASE||"").replace(/\/$/,"");
  const token=String(process.env.SCIM_E2E_TOKEN||"");
  const configuredUser=String(process.env.SCIM_E2E_USERNAME||"");
  if(!base||!/^tr_scim_secret_[A-Za-z0-9_-]{40,100}$/.test(token)){
    console.error("SCIM_E2E_FAIL invalid test configuration");
    return;
  }
  const domain=configuredUser.includes("@")?configuredUser.split("@").pop():"scim-e2e.invalid";
  const username=`e2e-${crypto.randomUUID().replaceAll("-","").slice(0,16)}@${domain}`;
  const externalId=`trustrelay-scim-e2e-${crypto.randomUUID().replaceAll("-","")}`;
  const origin=new URL(base).origin;
  const steps=[];
  const sleep=ms=>new Promise(r=>setTimeout(r,ms));
  const request=async(method,path,body,bearer=token)=>{
    const headers={Authorization:`Bearer ${bearer}`,Accept:"application/scim+json"};
    if(body!==undefined)headers["Content-Type"]="application/scim+json";
    const response=await fetch(base+path,{
      method,headers,body:body===undefined?undefined:JSON.stringify(body),
      signal:AbortSignal.timeout(15000)
    });
    const raw=await response.text();
    let json=null;try{json=raw?JSON.parse(raw):null}catch{}
    return{status:response.status,json,raw:raw.slice(0,240)};
  };
  const must=(condition,message)=>{if(!condition)throw new Error(message)};
  try{
    for(let i=0;i<30;i++){
      try{
        const r=await fetch(origin+"/version",{signal:AbortSignal.timeout(5000)});
        if(r.ok){
          const v=await r.json();
          if(!RENDER_GIT_COMMIT||v.commit===RENDER_GIT_COMMIT)break;
        }
      }catch{}
      if(i===29)throw new Error("staging did not route to current commit");
      await sleep(2000);
    }

    const badToken="tr_scim_secret_"+crypto.randomUUID().replaceAll("-","")+"xxxxxxxxxxxxxxxx";
    let r=await request("GET","/ServiceProviderConfig",undefined,badToken);
    steps.push(["invalid_bearer",r.status]);must(r.status===401,`invalid bearer ${r.status}`);

    r=await request("GET","/ServiceProviderConfig");
    steps.push(["service_provider",r.status]);
    must(r.status===200&&r.json?.patch?.supported===true&&r.json?.filter?.supported===true,`service provider ${r.status} ${r.raw}`);

    const userSchema="urn:ietf:params:scim:schemas:core:2.0:User";
    r=await request("POST","/Users",{
      schemas:[userSchema],userName:username,externalId,
      name:{givenName:"SCIM",familyName:"E2E"},displayName:"SCIM E2E User",
      title:"E2E Initial",active:true,emails:[{value:username,type:"work",primary:true}]
    });
    steps.push(["create",r.status]);must(r.status===201,`create ${r.status} ${r.raw}`);
    const userId=String(r.json?.id||"");must(userId,"missing user id");

    r=await request("GET","/Users?filter="+encodeURIComponent(`userName eq "${username}"`));
    steps.push(["filter",r.status]);
    must(r.status===200&&(r.json?.Resources||[]).some(x=>x.id===userId),`filter ${r.status} ${r.raw}`);

    r=await request("PUT","/Users/"+encodeURIComponent(userId),{
      schemas:[userSchema],userName:username,externalId,
      name:{givenName:"SCIM",familyName:"E2E"},displayName:"SCIM E2E Updated",
      title:"E2E Updated",active:true,emails:[{value:username,type:"work",primary:true}]
    });
    steps.push(["put",r.status]);
    must(r.status===200&&r.json?.displayName==="SCIM E2E Updated"&&r.json?.title==="E2E Updated",`put ${r.status} ${r.raw}`);

    const patchSchema="urn:ietf:params:scim:api:messages:2.0:PatchOp";
    r=await request("PATCH","/Users/"+encodeURIComponent(userId),{
      schemas:[patchSchema],Operations:[{op:"Replace",path:"active",value:false}]
    });
    steps.push(["suspend",r.status]);must(r.status===200&&r.json?.active===false,`suspend ${r.status} ${r.raw}`);

    r=await request("PATCH","/Users/"+encodeURIComponent(userId),{
      schemas:[patchSchema],Operations:[{op:"Replace",path:"active",value:true}]
    });
    steps.push(["reactivate",r.status]);must(r.status===200&&r.json?.active===true,`reactivate ${r.status} ${r.raw}`);

    r=await request("DELETE","/Users/"+encodeURIComponent(userId));
    steps.push(["delete",r.status]);must(r.status===204,`delete ${r.status} ${r.raw}`);

    r=await request("GET","/Users/"+encodeURIComponent(userId));
    steps.push(["post_delete_get",r.status]);must(r.status===200&&r.json?.active===false,`post-delete ${r.status} ${r.raw}`);

    console.log("SCIM_E2E_PASS "+JSON.stringify({steps}));
  }catch(error){
    console.error("SCIM_E2E_FAIL "+JSON.stringify({steps,error:String(error?.message||error)}));
  }
}

server.listen(PORT,"0.0.0.0",()=>{
  console.log(`TrustRelay ${VERSION} (${ENVIRONMENT}) listening on ${PORT}`);
  setTimeout(()=>{void runStagingScimE2E()},1000);
});
