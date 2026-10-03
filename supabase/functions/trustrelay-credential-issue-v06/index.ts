
const URL=Deno.env.get("SUPABASE_URL")||"";
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function secret(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function headers(){const k=secret();const h={"apikey":k,"content-type":"application/json","accept":"application/json"};if(k&&!k.startsWith("sb_secret_"))h["authorization"]="Bearer "+k;return h}
function sub(req){const a=req.headers.get("authorization")||"",t=a.replace(/^Bearer\s+/i,""),p=t.split(".")[1];if(!p)throw new Error("auth");const s=p.replaceAll("-","+").replaceAll("_","/")+"===".slice((p.length+3)%4);return JSON.parse(atob(s)).sub}
async function rpc(name,body){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:headers(),body:JSON.stringify(body||{})});const d=await r.json();if(!r.ok||d?.ok===false)throw{status:Number(d?.status)||r.status||400,code:d?.code||"REQUEST_REJECTED"};return d}
async function jsonBody(req,max=16384){const raw=await req.text();if(raw.length>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON"}}}
function id(p){return p+crypto.randomUUID().replaceAll("-","")}
function b64(bytes){let s="";for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/,"")}
function b64text(t){return b64(new TextEncoder().encode(t))}
function parse(v,f){if(v==null||v==="")return f;if(typeof v!=="string")return v;try{return JSON.parse(v)}catch{return f}}
function canon(v){if(Array.isArray(v))return v.map(canon);if(v&&typeof v==="object")return Object.keys(v).sort().reduce((a,k)=>(a[k]=canon(v[k]),a),{});return v}
async function hash64(t){return b64(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(t))))}
async function generateSigningKey(){
  const pair=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const pub=await crypto.subtle.exportKey("jwk",pair.publicKey),priv=await crypto.subtle.exportKey("jwk",pair.privateKey);
  const thumb=await hash64(JSON.stringify({crv:pub.crv,kty:pub.kty,x:pub.x,y:pub.y}));
  return {pub,priv,thumb,kid:"trk_"+thumb.slice(0,20)};
}
async function activeKey(){
  let current=null;
  try{current=await rpc("trustrelay_get_active_signing_key_v06",{})}
  catch(e){if(e?.code!=="SIGNING_KEY_UNAVAILABLE")throw e}
  if(current&&!current.rotationRequired)return current;
  const next=await generateSigningKey();
  await rpc("trustrelay_rotate_signing_key_v12",{
    p_kid:next.kid,p_public_jwk:JSON.stringify(next.pub),p_private_jwk:JSON.stringify(next.priv),
    p_public_thumbprint:next.thumb,p_force:Boolean(current?.rotationRequired)
  });
  return await rpc("trustrelay_get_active_signing_key_v06",{});
}
Deno.serve(async req=>{
 try{
  const uid=sub(req),v=await jsonBody(req),grantId=String(v.grantId||"").trim();
  if(!grantId)throw{status:400,code:"GRANT_ID_REQUIRED"};
  await rpc("trustrelay_ensure_account_v06",{p_auth_user_id:uid,p_display_name:null});
  await rpc("trustrelay_get_grant_v06",{p_auth_user_id:uid,p_grant_id:grantId});
  const refreshed=await rpc("trustrelay_refresh_grant_status_v06",{p_grant_id:grantId});
  const g=refreshed.grant;
  if(g.status!=="active")throw{status:409,code:"PENDING_VERIFICATION"};
  const k=await activeKey();
  const assurance=await rpc("trustrelay_get_grant_assurance_v08",{p_grant_id:g.id});
  const assuranceAtIssue={
    principal:assurance?.principal||null,
    representative:assurance?.representative||null
  };
  const policy={
    grantId:g.id,version:g.grant_version||1,
    principalPersonId:g.principal_person_id,representativePersonId:g.representative_person_id,
    allowed:parse(g.allowed_json,[]),prohibited:parse(g.prohibited_json,[]),
    resources:parse(g.resources_json,[]),rules:parse(g.rules_json,{}),escalation:parse(g.escalation_json,{}),
    validFrom:g.valid_from,validUntil:g.valid_until,
    assuranceAtIssue
  };
  const now=Math.floor(Date.now()/1000),end=Math.floor(new Date(g.valid_until).getTime()/1000),exp=Math.min(end,now+86400);
  if(!Number.isFinite(exp)||exp<=now)throw{status:409,code:"GRANT_EXPIRED"};
  const jti=id("jti_"),claims={
    iss:"https://trustrelay.app",aud:"trustrelay-authority",sub:g.representative_person_id,
    jti,iat:now,nbf:now,exp,trv:"0.8",grant_id:g.id,grant_version:g.grant_version||1,
    principal_person_id:g.principal_person_id,representative_person_id:g.representative_person_id,
    policy_hash:await hash64(JSON.stringify(canon(policy))),assurance_at_issue:assuranceAtIssue,authority:policy
  };
  const head={alg:"ES256",typ:"trustrelay-authority+jwt",kid:k.kid};
  const input=b64text(JSON.stringify(head))+"."+b64text(JSON.stringify(claims));
  const key=await crypto.subtle.importKey("jwk",k.privateJwk,{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
  const sig=new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key,new TextEncoder().encode(input)));
  const token=input+"."+b64(sig);
  const stored=await rpc("trustrelay_store_credential_v06",{
    p_id:id("cred_"),p_grant_id:g.id,p_jti:jti,p_kid:k.kid,p_token:token,p_claims_json:JSON.stringify(claims),
    p_issued_at:new Date(now*1000).toISOString(),p_expires_at:new Date(exp*1000).toISOString()
  });
  return Response.json({token,credential:{id:stored.credential.id,jti,kid:k.kid,alg:"ES256",issuedAt:stored.credential.issued_at,expiresAt:stored.credential.expires_at,assuranceAtIssue}},{status:201,headers:{"cache-control":"no-store"}});
 }catch(e){return Response.json({error:{code:e?.code||"AUTH_REQUIRED"}},{status:Number(e?.status)||401})}
});