import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT=path.dirname(fileURLToPath(import.meta.url));
const PORT=Number(process.env.PORT||10000);
const SUPABASE_URL=String(process.env.SUPABASE_URL||"").replace(/\/$/,"");
const SUPABASE_PUBLISHABLE_KEY=String(process.env.SUPABASE_PUBLISHABLE_KEY||"");
const ENVIRONMENT=String(process.env.TRUSTRELAY_ENVIRONMENT||"staging");
const VERSION=String(process.env.TRUSTRELAY_APP_VERSION||"1.0.0");
const BODY_LIMIT=Math.max(1024,Number(process.env.TRUSTRELAY_BODY_LIMIT_BYTES||262144));
const REQUEST_TIMEOUT=Math.max(1000,Number(process.env.TRUSTRELAY_REQUEST_TIMEOUT_MS||8000));

if(!SUPABASE_URL||!SUPABASE_PUBLISHABLE_KEY){
  console.error("SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY are required");
  process.exit(1);
}

const supabaseOrigin=new URL(SUPABASE_URL).origin;
const supabaseWs=supabaseOrigin.replace(/^https:/,"wss:");
const csp=[
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "script-src 'self' https://cdn.jsdelivr.net",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  `connect-src 'self' ${supabaseOrigin} ${supabaseWs} https://api.stripe.com https://checkout.stripe.com`,
  "form-action 'self' https://checkout.stripe.com",
  "upgrade-insecure-requests"
].join("; ");

const types={
  ".html":"text/html; charset=utf-8",".js":"text/javascript; charset=utf-8",
  ".mjs":"text/javascript; charset=utf-8",".css":"text/css; charset=utf-8",
  ".json":"application/json; charset=utf-8",".svg":"image/svg+xml",
  ".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".webp":"image/webp",
  ".ico":"image/x-icon",".txt":"text/plain; charset=utf-8",".map":"application/json; charset=utf-8"
};

function headers(extra={}){
  return {
    "Content-Security-Policy":csp,
    "Strict-Transport-Security":"max-age=31536000; includeSubDomains",
    "X-Content-Type-Options":"nosniff",
    "X-Frame-Options":"DENY",
    "Referrer-Policy":"strict-origin-when-cross-origin",
    "Permissions-Policy":"camera=(), microphone=(), geolocation=(), payment=(self)",
    "Cross-Origin-Opener-Policy":"same-origin",
    ...extra
  };
}
function sendJson(res,status,obj,extra={}){
  const body=JSON.stringify(obj);
  res.writeHead(status,headers({"Content-Type":"application/json; charset=utf-8","Content-Length":Buffer.byteLength(body),"Cache-Control":"no-store",...extra}));
  res.end(body);
}
function safeFile(urlPath){
  let decoded;
  try{decoded=decodeURIComponent(urlPath)}catch{return null}
  if(decoded.includes("\0"))return null;
  let rel=decoded.replace(/^\/+/, "");
  if(!rel)rel="index.html";
  if(rel.endsWith("/"))rel+="index.html";
  const candidate=path.resolve(ROOT,rel);
  if(candidate!==ROOT&&!candidate.startsWith(ROOT+path.sep))return null;
  return candidate;
}
async function readBody(req){
  const chunks=[];let size=0;
  for await(const chunk of req){
    size+=chunk.length;
    if(size>BODY_LIMIT)throw Object.assign(new Error("BODY_TOO_LARGE"),{status:413});
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

const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url||"/","http://localhost");
  if(url.pathname==="/healthz"){
    return sendJson(res,200,{status:"ok",service:"trustrelay-web",version:VERSION,environment:ENVIRONMENT});
  }
  if(url.pathname==="/version"){
    return sendJson(res,200,{version:VERSION,environment:ENVIRONMENT});
  }
  if(url.pathname==="/runtime-config.json"){
    return sendJson(res,200,{
      supabaseUrl:SUPABASE_URL,
      supabasePublishableKey:SUPABASE_PUBLISHABLE_KEY,
      environment:ENVIRONMENT,
      appVersion:VERSION
    });
  }
  if(url.pathname.startsWith("/v1/decisions/")){
    return proxyPartner(req,res,url);
  }
  if(!["GET","HEAD"].includes(req.method||"GET")){
    return sendJson(res,405,{error:{code:"METHOD_NOT_ALLOWED"}},{Allow:"GET, HEAD"});
  }

  const file=safeFile(url.pathname);
  if(!file)return sendJson(res,400,{error:{code:"INVALID_PATH"}});
  let st;
  try{st=fs.statSync(file)}catch{return sendJson(res,404,{error:{code:"NOT_FOUND"}})}
  let actual=file;
  if(st.isDirectory())actual=path.join(file,"index.html");
  try{
    const data=fs.readFileSync(actual);
    const ext=path.extname(actual).toLowerCase();
    const html=ext===".html";
    res.writeHead(200,headers({
      "Content-Type":types[ext]||"application/octet-stream",
      "Content-Length":data.length,
      "Cache-Control":html?"no-store":"public, max-age=300"
    }));
    if(req.method==="HEAD")res.end();else res.end(data);
  }catch{
    sendJson(res,404,{error:{code:"NOT_FOUND"}});
  }
});

server.listen(PORT,"0.0.0.0",()=>console.log(`TrustRelay ${VERSION} (${ENVIRONMENT}) listening on ${PORT}`));
