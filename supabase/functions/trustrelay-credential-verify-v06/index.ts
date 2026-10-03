
const URL=Deno.env.get("SUPABASE_URL")||"";
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function secret(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function headers(){const k=secret();const h={"apikey":k,"content-type":"application/json","accept":"application/json"};if(k&&!k.startsWith("sb_secret_"))h["authorization"]="Bearer "+k;return h}
async function rpc(name,body){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:headers(),body:JSON.stringify(body||{})});const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}if(!r.ok||d?.ok===false)throw{status:Number(d?.status)||r.status||400,code:d?.code||"REQUEST_REJECTED"};return d}
function b64decode(v){const s=v.replaceAll("-","+").replaceAll("_","/")+"===".slice((v.length+3)%4),r=atob(s);return new Uint8Array([...r].map(c=>c.charCodeAt(0)))}
function jsonpart(v){return JSON.parse(new TextDecoder().decode(b64decode(v)))}
function id(p){return p+crypto.randomUUID().replaceAll("-","")}
async function hex(t){return[...new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(t)))].map(b=>b.toString(16).padStart(2,"0")).join("")}
const PUBLIC_HEADERS={"cache-control":"no-store","x-content-type-options":"nosniff","x-frame-options":"DENY","referrer-policy":"no-referrer","permissions-policy":"camera=(), microphone=(), geolocation=()","access-control-allow-origin":"*","access-control-allow-methods":"POST, OPTIONS","access-control-allow-headers":"content-type, apikey, authorization"};
const VERIFY_GLOBAL_RPM=600;
const VERIFY_CREDENTIAL_RPM=120;
async function limit(bucket,limit){
  const d=await rpc("consume_rate_limit_v05",{p_bucket_key:bucket,p_limit:limit,p_window_seconds:60});
  const x=Array.isArray(d)?d[0]:d;
  return {allowed:Boolean(x?.allowed),remaining:Number(x?.remaining||0),resetAt:Number(x?.reset_at||0)};
}
function out(data,status=200,extra={}){return Response.json(data,{status,headers:{...PUBLIC_HEADERS,...extra}})}

Deno.serve(async req=>{
 try{
   if(req.method==="OPTIONS")return new Response(null,{status:204,headers:PUBLIC_HEADERS});
   if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405,{Allow:"POST"});
   const contentLength=Number(req.headers.get("content-length")||0);
   if(Number.isFinite(contentLength)&&contentLength>32768)return out({error:{code:"PAYLOAD_TOO_LARGE"}},413);
   const raw=await req.text();
   if(new TextEncoder().encode(raw).byteLength>32768)return out({error:{code:"PAYLOAD_TOO_LARGE"}},413);
   let v;try{v=raw?JSON.parse(raw):{}}catch{return out({error:{code:"INVALID_JSON"}},400)}
   const token=typeof v.token==="string"?v.token.trim():"";
   if(token.length>16384)return out({error:{code:"TOKEN_TOO_LARGE"}},413);
   if(!token)return out({error:{code:"TOKEN_REQUIRED"}},400);
   const parts=token.split(".");
   if(parts.length!==3||parts.some(x=>!x||x.length>12288))return out({valid:false,reasonCode:"MALFORMED"});
   if(parts[0].length>2048||parts[1].length>12288||parts[2].length>2048)return out({valid:false,reasonCode:"MALFORMED"});
   let head,claims;try{head=jsonpart(parts[0]);claims=jsonpart(parts[1])}catch{return out({valid:false,reasonCode:"MALFORMED"})}
   if(
     head?.alg!=="ES256"||head?.typ!=="trustrelay-authority+jwt"||
     typeof head?.kid!=="string"||head.kid.length<8||head.kid.length>128||
     claims?.iss!=="https://trustrelay.app"||claims?.aud!=="trustrelay-authority"||
     typeof claims?.jti!=="string"||claims.jti.length<8||claims.jti.length>128||
     typeof claims?.grant_id!=="string"||claims.grant_id.length<8||claims.grant_id.length>128||
     typeof claims?.sub!=="string"||claims.sub.length<8||claims.sub.length>128||
     !Number.isFinite(Number(claims?.iat))||!Number.isFinite(Number(claims?.nbf))||!Number.isFinite(Number(claims?.exp))
   )return out({valid:false,reasonCode:"MALFORMED"});
   const now=Math.floor(Date.now()/1000);
   if(Number(claims.iat)>now+300||Number(claims.nbf)>now+300||Number(claims.exp)<=Number(claims.iat))return out({valid:false,reasonCode:"MALFORMED"});
   const globalLimit=await limit("public:credential-verify:global",VERIFY_GLOBAL_RPM);
   if(!globalLimit.allowed){
     const retry=Math.max(1,globalLimit.resetAt-now);
     return out({error:{code:"RATE_LIMITED"}},429,{"Retry-After":String(retry)});
   }
   const ctx=await rpc("trustrelay_get_credential_context_v06",{p_jti:claims.jti});
   const credentialLimit=await limit("public:credential-verify:"+claims.jti,VERIFY_CREDENTIAL_RPM);
   if(!credentialLimit.allowed){
     const retry=Math.max(1,credentialLimit.resetAt-now);
     return out({error:{code:"RATE_LIMITED"}},429,{"Retry-After":String(retry)});
   }
   const c=ctx;
   try{
     const refreshed=await rpc("trustrelay_refresh_grant_status_v06",{p_grant_id:c.grant.id});
     if(refreshed?.grant)c.grant=refreshed.grant;
   }catch{}
   let valid=true,reason="VALID",assurance=null;
   if(c.credential.token!==token){valid=false;reason="TOKEN_MISMATCH"}
   else if(c.credential.status!=="active"){valid=false;reason="CREDENTIAL_"+String(c.credential.status||"INACTIVE").toUpperCase()}
   else if(c.revocation){valid=false;reason="CREDENTIAL_REVOKED"}
   else if(c.grant.status!=="active"){valid=false;reason="GRANT_"+String(c.grant.status||"INACTIVE").toUpperCase()}
   else if(c.signingKey.status==="revoked"){valid=false;reason="SIGNING_KEY_REVOKED"}
   else{
     const now=Math.floor(Date.now()/1000);
     if(Number(claims.nbf)>now){valid=false;reason="NOT_YET_VALID"}
     else if(Number(claims.exp)<=now){valid=false;reason="EXPIRED"}
   }
   if(valid){
     const key=await crypto.subtle.importKey("jwk",c.signingKey.publicJwk,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
     const ok=await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,b64decode(parts[2]),new TextEncoder().encode(parts[0]+"."+parts[1]));
     if(!ok){valid=false;reason="SIGNATURE_INVALID"}
   }
   if(valid){
     try{assurance=await rpc("trustrelay_get_grant_assurance_v08",{p_grant_id:c.grant.id})}catch{}
   }
   try{await rpc("trustrelay_record_credential_verification_v06",{
     p_id:id("verify_"),p_jti:claims.jti,p_kid:head.kid,p_valid:valid,p_reason_code:reason,
     p_request_fingerprint:await hex(token),p_metadata_json:"{}"
   })}catch{}
   return out({valid,reasonCode:reason,credential:{jti:claims.jti,kid:head.kid,expiresAt:claims.exp?new Date(Number(claims.exp)*1000).toISOString():null,assuranceAtIssue:claims.assurance_at_issue||claims.authority?.assuranceAtIssue||null},authority:valid?claims.authority:null,currentAssurance:valid?{principal:assurance?.principal||null,representative:assurance?.representative||null}:null});
 }catch{return out({valid:false,reasonCode:"MALFORMED_OR_UNKNOWN"})}
});