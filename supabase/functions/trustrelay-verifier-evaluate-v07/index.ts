
const URL=Deno.env.get("SUPABASE_URL")||"";
const CANONICAL_APP_ORIGIN=URL.includes("msfrbsnihylfynrtdgxe")?"https://trustrelay-production.onrender.com":URL.includes("kdvroylluosshcjmfbfq")?"https://trustrelay-staging.onrender.com":"";
const APP_ORIGIN=(Deno.env.get("TRUSTRELAY_APP_ORIGIN")||CANONICAL_APP_ORIGIN).replace(/\/$/,"");
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function pub(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||""}
function sec(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
async function sha256Hex(text){const d=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(text)));return [...d].map(b=>b.toString(16).padStart(2,"0")).join("")}
async function hmacHex(secret,text){const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);const sig=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(text)));return [...sig].map(b=>b.toString(16).padStart(2,"0")).join("")}
async function parse(r){const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}return{ok:r.ok,status:r.status,data:d}}
function serviceHeaders(){
  const k=sec();
  const h={apikey:k,"content-type":"application/json",accept:"application/json"};
  if(k&&!k.startsWith("sb_secret_"))h.authorization="Bearer "+k;
  return h;
}
async function rpcService(name,payload){
  const r=await fetch(URL+"/rest/v1/rpc/"+name,{
    method:"POST",headers:serviceHeaders(),body:JSON.stringify(payload||{})
  });
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||503,code:x.data?.code||"DATABASE_ERROR"};
  if(x.data?.ok===false)throw{status:Number(x.data?.status)||403,code:x.data?.code||"REQUEST_DENIED"};
  return x.data;
}
function jwtPayload(authorization){
  try{
    const token=String(authorization||"").replace(/^Bearer\s+/i,"");
    const p=token.split(".")[1];if(!p)return{};
    const s=p.replaceAll("-","+").replaceAll("_","/")+"===".slice((p.length+3)%4);
    return JSON.parse(atob(s));
  }catch{return{}}
}
async function user(req){
  const auth=req.headers.get("authorization")||"";
  if(!/^Bearer\s+\S+/i.test(auth))throw{status:401,code:"AUTH_REQUIRED"};
  const r=await fetch(URL+"/auth/v1/user",{headers:{apikey:pub(),authorization:auth,accept:"application/json"}});
  if(!r.ok)throw{status:401,code:"INVALID_SESSION"};
  const u=await r.json();if(!u?.id)throw{status:401,code:"INVALID_SESSION"};return u;
}
function corsHeaders(req){
  const origin=req?.headers?.get?.("origin")||"";
  if(!origin||!CANONICAL_APP_ORIGIN||origin!==CANONICAL_APP_ORIGIN)return{};
  return {
    "access-control-allow-origin":origin,
    "access-control-allow-methods":"POST, OPTIONS",
    "access-control-allow-headers":"authorization, apikey, content-type",
    "access-control-max-age":"86400",
    "vary":"Origin"
  };
}
function corsPreflight(req){
  const origin=req.headers.get("origin")||"";
  if(!CANONICAL_APP_ORIGIN||origin!==CANONICAL_APP_ORIGIN)return Response.json({error:{code:"CORS_ORIGIN_DENIED"}},{status:403});
  return new Response(null,{status:204,headers:corsHeaders(req)});
}
function out(data,status=200,req=null){
  return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff",...corsHeaders(req)}});
}
async function jsonBody(req,max=65536){const contentLength=Number(req.headers.get("content-length")||0);if(Number.isFinite(contentLength)&&contentLength>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};const raw=await req.text();if(new TextEncoder().encode(raw).byteLength>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON"}}}
Deno.serve(async req=>{
  try{
    if(req.method==="OPTIONS")return corsPreflight(req);
    if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405,req);
    const authorization=req.headers.get("authorization")||"";
    const u=await user(req);
    const body=await jsonBody(req);
    const orgId=String(body.orgId||"").trim();
    if(!orgId||orgId.length>160)return out({error:{code:"ORGANIZATION_REQUIRED"}},400,req);

    const serviceKey=sec();
    if(!serviceKey)return out({error:{code:"INTERNAL_SERVICE_AUTH_UNAVAILABLE"}},503,req);

    const claims=jwtPayload(authorization);
    const sessionId=String(claims.session_id||"").trim();
    const access=await rpcService("trustrelay_portal_session_context_v12",{
      p_auth_user_id:u.id,p_session_id:sessionId,p_org_id:orgId
    });

    const partnerBody={...body};
    delete partnerBody.orgId;
    const partnerRaw=JSON.stringify(partnerBody);
    const timestamp=String(Math.floor(Date.now()/1000));
    const bodyHash=await sha256Hex(partnerRaw);
    const canonical=["v1",timestamp,orgId,u.id,"POST","/v1/decisions/evaluate",bodyHash].join("\n");
    const internalSignature=await hmacHex(serviceKey,canonical);

    const partner=await fetch(URL+"/functions/v1/trustrelay-partner-v07/v1/decisions/evaluate",{
      method:"POST",
      headers:{
        apikey:pub(),
        "x-trustrelay-internal-org":orgId,
        "x-trustrelay-internal-user":u.id,
        "x-trustrelay-internal-ts":timestamp,
        "x-trustrelay-internal-sig":internalSignature,
        "content-type":"application/json",
        accept:"application/json"
      },
      body:partnerRaw
    });
    const result=await parse(partner);
    if(!result.ok)return out(result.data||{error:{code:"PARTNER_API_ERROR"}},result.status,req);

    if(result.data?.decision)result.data.decision.source="portal";
    result.data.portal={organizationId:orgId,role:access.role||null};
    return out(result.data,200,req);
  }catch(e){
    const status=Number(e?.status)||500;
    return out({error:{code:e?.code||"INTERNAL_ERROR"}},status,req);
  }
});