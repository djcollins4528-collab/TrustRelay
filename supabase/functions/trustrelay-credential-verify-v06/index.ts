
const URL=Deno.env.get("SUPABASE_URL")||"";
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function secret(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||""}
function headers(){const k=secret();const h={"apikey":k,"content-type":"application/json","accept":"application/json"};if(k&&!k.startsWith("sb_secret_"))h["authorization"]="Bearer "+k;return h}
async function rpc(name,body){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:headers(),body:JSON.stringify(body||{})});const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}if(!r.ok||d?.ok===false)throw{status:Number(d?.status)||r.status||400,code:d?.code||"REQUEST_REJECTED"};return d}
function b64decode(v){const s=v.replaceAll("-","+").replaceAll("_","/")+"===".slice((v.length+3)%4),r=atob(s);return new Uint8Array([...r].map(c=>c.charCodeAt(0)))}
function jsonpart(v){return JSON.parse(new TextDecoder().decode(b64decode(v)))}
function id(p){return p+crypto.randomUUID().replaceAll("-","")}
async function hex(t){return[...new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(t)))].map(b=>b.toString(16).padStart(2,"0")).join("")}

const OUT_HEADERS={"cache-control":"no-store","x-content-type-options":"nosniff"};
async function boundedJson(req,maxBytes=65536){
  const declared=Number(req.headers.get("content-length")||0);
  if(Number.isFinite(declared)&&declared>maxBytes)throw{status:413,code:"REQUEST_TOO_LARGE"};
  const raw=await req.text();
  if(new TextEncoder().encode(raw).length>maxBytes)throw{status:413,code:"REQUEST_TOO_LARGE"};
  try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"JSON_INVALID"}}
}
Deno.serve(async req=>{
 try{
   if(req.method!=="POST")return Response.json({error:{code:"METHOD_NOT_ALLOWED"}},{status:405,headers:OUT_HEADERS});
   const v=await boundedJson(req),token=typeof v.token==="string"?v.token.trim():"";
   if(!token)return Response.json({error:{code:"TOKEN_REQUIRED"}},{status:400,headers:OUT_HEADERS});
   if(token.length>32768)return Response.json({valid:false,reasonCode:"MALFORMED"},{headers:OUT_HEADERS});
   const parts=token.split(".");
   if(parts.length!==3||parts[0].length>4096||parts[1].length>24576||parts[2].length>4096||
      parts.some(p=>!p||!/^[A-Za-z0-9_-]+$/.test(p)))return Response.json({valid:false,reasonCode:"MALFORMED"},{headers:OUT_HEADERS});
   const head=jsonpart(parts[0]),claims=jsonpart(parts[1]);
   if(head.alg!=="ES256"||typeof head.kid!=="string"||head.kid.length>160||
      typeof claims.jti!=="string"||claims.jti.length>200)return Response.json({valid:false,reasonCode:"MALFORMED"},{headers:OUT_HEADERS});
   const c=await rpc("trustrelay_get_credential_context_v06",{p_jti:claims.jti});
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
   return Response.json({valid,reasonCode:reason,credential:{jti:claims.jti,kid:head.kid,expiresAt:claims.exp?new Date(Number(claims.exp)*1000).toISOString():null,assuranceAtIssue:claims.assurance_at_issue||claims.authority?.assuranceAtIssue||null},authority:valid?claims.authority:null,currentAssurance:valid?{principal:assurance?.principal||null,representative:assurance?.representative||null}:null},{headers:OUT_HEADERS});
 }catch(e){
   if(e?.status)return Response.json({error:{code:e.code||"REQUEST_REJECTED"}},{status:Number(e.status)||400,headers:OUT_HEADERS});
   return Response.json({valid:false,reasonCode:"MALFORMED_OR_UNKNOWN"},{status:200,headers:OUT_HEADERS});
 }
});