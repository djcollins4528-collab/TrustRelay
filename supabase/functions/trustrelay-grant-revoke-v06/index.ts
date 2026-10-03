
const URL=Deno.env.get("SUPABASE_URL")||"";
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function secret(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function headers(){const k=secret();const h={"apikey":k,"content-type":"application/json","accept":"application/json"};if(k&&!k.startsWith("sb_secret_"))h["authorization"]="Bearer "+k;return h}
function sub(req){const a=req.headers.get("authorization")||"",t=a.replace(/^Bearer\s+/i,""),p=t.split(".")[1];if(!p)throw new Error("auth");const s=p.replaceAll("-","+").replaceAll("_","/")+"===".slice((p.length+3)%4);return JSON.parse(atob(s)).sub}
async function rpc(name,body){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:headers(),body:JSON.stringify(body||{})});const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}if(!r.ok||d?.ok===false)throw{status:Number(d?.status)||r.status||400,code:d?.code||"REQUEST_REJECTED"};return d}
async function jsonBody(req,max=16384){const raw=await req.text();if(raw.length>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON"}}}
async function hmacHex(secret,text){const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);const sig=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(text)));return[...sig].map(b=>b.toString(16).padStart(2,"0")).join("")}
async function dispatch(orgId,eventType,eventId,event){
  try{
    const queued=await rpc("trustrelay_queue_webhooks_v07",{
      p_org_id:orgId,p_event_type:eventType,p_event_id:eventId,p_payload_json:JSON.stringify(event)
    });
    if(queued?.ok) await rpc("trustrelay_dispatch_due_webhooks_v09",{p_limit:50});
  }catch{}
}
async function fanout(grant){
  try{
    const [orgs,creds]=await Promise.all([
      rpc("trustrelay_orgs_for_grant_v07",{p_grant_id:grant.id}),
      rpc("trustrelay_credentials_for_grant_v07",{p_grant_id:grant.id})
    ]);
    const orgIds=Array.isArray(orgs?.organizationIds)?orgs.organizationIds:[];
    if(!orgIds.length)return;
    const now=new Date().toISOString();
    for(const orgId of orgIds){
      const grantEventId="evt_"+crypto.randomUUID().replaceAll("-","");
      const grantEvent={id:grantEventId,type:"grant.revoked",createdAt:now,organizationId:orgId,data:{grantId:grant.id,revokedAt:grant.revoked_at||now,reason:grant.revocation_reason||null}};
      await dispatch(orgId,"grant.revoked",grantEventId,grantEvent);
      for(const c of (creds?.credentials||[])){
        if(c.status!=="revoked")continue;
        const eventId="evt_"+crypto.randomUUID().replaceAll("-","");
        const event={id:eventId,type:"credential.revoked",createdAt:now,organizationId:orgId,data:{grantId:grant.id,credentialId:c.id,jti:c.jti,kid:c.kid,revokedAt:c.revokedAt||now}};
        await dispatch(orgId,"credential.revoked",eventId,event);
      }
    }
  }catch{}
}
Deno.serve(async req=>{
  try{
    const uid=sub(req),v=await jsonBody(req);
    await rpc("trustrelay_ensure_account_v06",{p_auth_user_id:uid,p_display_name:null});
    const grantId=String(v.grantId||"").trim();
    if(!grantId)throw{status:400,code:"GRANT_ID_REQUIRED"};
    const result=await rpc("trustrelay_revoke_grant_v06",{p_auth_user_id:uid,p_grant_id:grantId,p_reason:String(v.reason||"").slice(0,500)});
    if(result?.grant&&!result.alreadyRevoked)EdgeRuntime.waitUntil(fanout(result.grant));
    return Response.json(result,{headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}});
  }catch(e){return Response.json({error:{code:e?.code||"AUTH_REQUIRED"}},{status:Number(e?.status)||401,headers:{"cache-control":"no-store"}})}
});