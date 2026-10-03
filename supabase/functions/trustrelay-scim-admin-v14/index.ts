const SUPABASE_URL=(Deno.env.get("SUPABASE_URL")||"").replace(/\/$/,"");
const CANONICAL_APP_ORIGIN=SUPABASE_URL.includes("msfrbsnihylfynrtdgxe")
  ?"https://trustrelay-production.onrender.com"
  :SUPABASE_URL.includes("kdvroylluosshcjmfbfq")
    ?"https://trustrelay-staging.onrender.com":"";
function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function secretKey(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function publishableKey(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||""}
const SECRET_KEY=secretKey(),PUBLISHABLE_KEY=publishableKey();

function cors(req){
  const origin=req.headers.get("origin")||"";
  if(!origin||origin!==CANONICAL_APP_ORIGIN)return {};
  return {"access-control-allow-origin":origin,"access-control-allow-methods":"POST, OPTIONS","access-control-allow-headers":"authorization, apikey, content-type","access-control-max-age":"86400","vary":"Origin"};
}
function out(req,data,status=200){return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff",...cors(req)}})}
function serviceHeaders(extra={}){
  const h={apikey:SECRET_KEY,accept:"application/json",...extra};
  if(SECRET_KEY&&!SECRET_KEY.startsWith("sb_secret_"))h.authorization="Bearer "+SECRET_KEY;
  return h;
}
async function parse(r){const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}return{ok:r.ok,status:r.status,data:d,text:t}}
async function body(req,max=32768){
  const raw=await req.text();if(new TextEncoder().encode(raw).byteLength>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};
  try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON"}}
}
async function userSession(req){
  const auth=req.headers.get("authorization")||"";
  if(!/^Bearer\s+\S+/i.test(auth))throw{status:401,code:"AUTH_REQUIRED"};
  const r=await fetch(SUPABASE_URL+"/auth/v1/user",{headers:{apikey:PUBLISHABLE_KEY,authorization:auth,accept:"application/json"}});
  if(!r.ok)throw{status:401,code:"INVALID_SESSION"};
  const user=await r.json();if(!user?.id)throw{status:401,code:"INVALID_SESSION"};
  return {user,authorization:auth};
}
async function userRpc(name,payload,authorization){
  const r=await fetch(SUPABASE_URL+"/rest/v1/rpc/"+name,{method:"POST",headers:{apikey:PUBLISHABLE_KEY,authorization,"content-type":"application/json",accept:"application/json"},body:JSON.stringify(payload||{})});
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR"};
  if(x.data?.ok===false)throw{status:Number(x.data.status)||400,code:x.data.code||"REQUEST_REJECTED",details:x.data};
  return x.data;
}
async function serviceRpc(name,payload){
  const r=await fetch(SUPABASE_URL+"/rest/v1/rpc/"+name,{method:"POST",headers:serviceHeaders({"content-type":"application/json"}),body:JSON.stringify(payload||{})});
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR"};
  if(x.data?.ok===false)throw{status:Number(x.data.status)||400,code:x.data.code||"REQUEST_REJECTED",details:x.data};
  return x.data;
}
function randomHex(bytes=16){const a=new Uint8Array(bytes);crypto.getRandomValues(a);return [...a].map(x=>x.toString(16).padStart(2,"0")).join("")}
function randomSecret(bytes=32){const a=new Uint8Array(bytes);crypto.getRandomValues(a);let s="";for(const b of a)s+=String.fromCharCode(b);return "tr_scim_secret_"+btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
async function sha256(v){const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(String(v)));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("")}
function endpoints(){
  return {
    scimBaseUrl:CANONICAL_APP_ORIGIN+"/scim/v2",
    oauthTokenUrl:CANONICAL_APP_ORIGIN+"/oauth2/token",
    serviceProviderConfigUrl:CANONICAL_APP_ORIGIN+"/scim/v2/ServiceProviderConfig"
  };
}
Deno.serve(async req=>{
  try{
    if(req.method==="OPTIONS"){
      if((req.headers.get("origin")||"")!==CANONICAL_APP_ORIGIN)return out(req,{error:{code:"CORS_ORIGIN_DENIED"}},403);
      return new Response(null,{status:204,headers:cors(req)});
    }
    if(req.method!=="POST")return out(req,{error:{code:"METHOD_NOT_ALLOWED"}},405);
    if(!SUPABASE_URL||!SECRET_KEY||!PUBLISHABLE_KEY||!CANONICAL_APP_ORIGIN)throw{status:503,code:"SCIM_ADMIN_NOT_CONFIGURED"};
    if((req.headers.get("origin")||"")!==CANONICAL_APP_ORIGIN)throw{status:403,code:"CORS_ORIGIN_DENIED"};

    const {authorization}=await userSession(req);
    const input=await body(req);
    const action=String(input.action||"");
    const orgId=String(input.orgId||"").trim();
    if(!orgId)throw{status:400,code:"ORGANIZATION_ID_REQUIRED"};

    const status=await userRpc("trustrelay_scim_admin_status_v14",{p_org_id:orgId},authorization);

    if(action==="status")return out(req,{...status,...endpoints()});

    if(action==="create_credential"||action==="rotate_credential"||action==="enable"||action==="rotate"){
      const role=String(input.defaultRole||status?.config?.defaultRole||"verifier");
      if(!["compliance","verifier","developer","auditor"].includes(role))throw{status:400,code:"SCIM_DEFAULT_ROLE_INVALID"};
      const days=Math.max(365,Math.min(1095,Number(input.expirationDays||365)||365));
      const expiresAt=new Date(Date.now()+days*86400000).toISOString();
      const clientId="tr_scim_"+randomHex(16);
      const clientSecret=randomSecret(32);
      const rotating=action==="rotate_credential"||action==="rotate";
      const label=String(input.label||(rotating?"Rotation":"Primary")).trim().slice(0,80)||"Primary";
      const result=await serviceRpc("trustrelay_scim_store_credential_v14",{
        p_org_id:orgId,p_actor_account_id:status.actorAccountId,
        p_client_id:clientId,p_secret_hash:await sha256(clientSecret),
        p_label:label,p_default_role:role,p_expires_at:expiresAt
      });
      return out(req,{
        ok:true,configured:true,status:"active",
        credential:{id:result.credentialId,clientId,clientSecret,bearerToken:clientSecret,expiresAt,shownOnce:true},
        providerKind:result.providerKind,defaultRole:role,
        endpoint:endpoints().scimBaseUrl,token:clientSecret,tokenLastFour:clientSecret.slice(-4),
        ...endpoints()
      },201);
    }

    if(action==="revoke_credential"){
      const id=String(input.credentialId||"").trim();if(!id)throw{status:400,code:"SCIM_CREDENTIAL_ID_REQUIRED"};
      const result=await serviceRpc("trustrelay_scim_revoke_credential_v14",{
        p_org_id:orgId,p_actor_account_id:status.actorAccountId,p_credential_id:id
      });
      return out(req,{...result,...endpoints()});
    }

    if(action==="policy"){
      const role=String(input.defaultRole||status?.config?.defaultRole||"verifier");
      if(!["compliance","verifier","developer","auditor"].includes(role))throw{status:400,code:"SCIM_DEFAULT_ROLE_INVALID"};
      const result=await serviceRpc("trustrelay_scim_set_policy_v14",{
        p_org_id:orgId,p_actor_account_id:status.actorAccountId,p_default_role:role,
        p_allow_static_bearer:input.allowStaticBearer!==false,
        p_group_sync_enabled:input.groupSyncEnabled!==false
      });
      return out(req,{...result,configured:true,status:status?.config?.status||"active",...endpoints()});
    }

    if(action==="disable"){
      const result=await serviceRpc("trustrelay_scim_disable_v14",{
        p_org_id:orgId,p_actor_account_id:status.actorAccountId
      });
      return out(req,{...result,configured:true,status:"disabled",...endpoints()});
    }

    throw{status:400,code:"ACTION_INVALID"};
  }catch(e){
    return out(req,{error:{code:e?.code||"SCIM_ADMIN_ERROR",details:e?.details||null}},Number(e?.status)||500);
  }
});