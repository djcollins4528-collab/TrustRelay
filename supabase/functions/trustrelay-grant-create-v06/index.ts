
const URL=Deno.env.get("SUPABASE_URL")||"";
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function secret(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function headers(){const k=secret();const h={"apikey":k,"content-type":"application/json","accept":"application/json"};if(k&&!k.startsWith("sb_secret_"))h["authorization"]="Bearer "+k;return h}
function sub(req){const a=req.headers.get("authorization")||"",t=a.replace(/^Bearer\s+/i,""),p=t.split(".")[1];if(!p)throw new Error("auth");const s=p.replaceAll("-","+").replaceAll("_","/")+"===".slice((p.length+3)%4);return JSON.parse(atob(s)).sub}
function id(p){return p+crypto.randomUUID().replaceAll("-","")}
function b64(bytes){let s="";for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/,"")}
function rand(){const v=new Uint8Array(32);crypto.getRandomValues(v);return b64(v)}
async function sha(t){return[...new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(t)))].map(b=>b.toString(16).padStart(2,"0")).join("")}
async function rpc(name,body){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:headers(),body:JSON.stringify(body)});const d=await r.json();if(!r.ok||d?.ok===false)throw{status:Number(d?.status)||r.status||400,code:d?.code||"REQUEST_REJECTED"};return d}
async function jsonBody(req,max=65536){const raw=await req.text();if(raw.length>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON"}}}
Deno.serve(async req=>{
  try{
    const uid=sub(req);
    const v=await jsonBody(req);
    await rpc("trustrelay_ensure_account_v06",{p_auth_user_id:uid,p_display_name:null});
    const email=String(v.representativeEmail||"").trim().toLowerCase();
    if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))throw{status:400,code:"INVALID_REPRESENTATIVE_EMAIL"};
    const allowed=Array.isArray(v.allowedActions)?v.allowedActions.filter(x=>typeof x==="string"&&x.trim()).map(x=>x.trim()):[];
    const prohibited=Array.isArray(v.prohibitedActions)?v.prohibitedActions.filter(x=>typeof x==="string"&&x.trim()).map(x=>x.trim()):[];
    const resources=Array.isArray(v.resources)?v.resources.filter(x=>typeof x==="string"&&x.trim()).map(x=>x.trim()):[];
    if(!allowed.length)throw{status:400,code:"ALLOWED_ACTION_REQUIRED"};
    if(!resources.length)throw{status:400,code:"RESOURCE_REQUIRED"};
    const from=v.validFrom?new Date(v.validFrom):new Date();
    const until=v.validUntil?new Date(v.validUntil):new Date(Date.now()+30*86400000);
    if(!Number.isFinite(from.getTime())||!Number.isFinite(until.getTime())||until<=from)throw{status:400,code:"INVALID_VALIDITY_WINDOW"};
    const raw=rand();
    const result=await rpc("trustrelay_create_grant_invite_v06",{
      p_auth_user_id:uid,p_grant_id:id("grant_"),p_invitation_id:id("invite_"),
      p_token_hash:await sha(raw),p_representative_email:email,
      p_valid_from:from.toISOString(),p_valid_until:until.toISOString(),
      p_allowed_json:JSON.stringify(allowed),p_prohibited_json:JSON.stringify(prohibited),
      p_rules_json:JSON.stringify(v.rules&&typeof v.rules==="object"&&!Array.isArray(v.rules)?v.rules:{}),
      p_resources_json:JSON.stringify(resources),
      p_escalation_json:JSON.stringify(v.escalation&&typeof v.escalation==="object"&&!Array.isArray(v.escalation)?v.escalation:{}),
      p_invitation_expires_at:new Date(Date.now()+7*86400000).toISOString()
    });
    return Response.json({grant:result.grant,invitation:{id:result.invitation.id,email:result.invitation.invite_email,expiresAt:result.invitation.expires_at,token:raw}},{status:201,headers:{"cache-control":"no-store"}});
  }catch(e){return Response.json({error:{code:e?.code||"AUTH_REQUIRED"}},{status:Number(e?.status)||401})}
});