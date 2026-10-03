const SUPABASE_URL=(Deno.env.get("SUPABASE_URL")||"").replace(/\/$/,"");
const CANONICAL_APP_ORIGIN=SUPABASE_URL.includes("msfrbsnihylfynrtdgxe")
  ?"https://trustrelay-production.onrender.com"
  :SUPABASE_URL.includes("kdvroylluosshcjmfbfq")
    ?"https://trustrelay-staging.onrender.com":"";

function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function publishableKey(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||""}
function secretKey(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
const PUBLISHABLE_KEY=publishableKey(),SECRET_KEY=secretKey();

function cors(req){
  const origin=req.headers.get("origin")||"";
  if(origin!==CANONICAL_APP_ORIGIN)return {};
  return {
    "access-control-allow-origin":origin,
    "access-control-allow-methods":"POST, OPTIONS",
    "access-control-allow-headers":"authorization, apikey, content-type",
    "access-control-max-age":"86400",
    "vary":"Origin"
  };
}
function out(req,data,status=200){
  return Response.json(data,{status,headers:{
    "cache-control":"no-store",
    "x-content-type-options":"nosniff",
    ...cors(req)
  }});
}
async function parse(r){
  const t=await r.text();let d=null;
  try{d=t?JSON.parse(t):null}catch{}
  return{ok:r.ok,status:r.status,data:d,text:t};
}
async function body(req,max=32768){
  const n=Number(req.headers.get("content-length")||0);
  if(Number.isFinite(n)&&n>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};
  const raw=await req.text();
  if(new TextEncoder().encode(raw).byteLength>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};
  try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON"}}
}
async function userSession(req){
  const auth=req.headers.get("authorization")||"";
  if(!/^Bearer\s+\S+/i.test(auth))throw{status:401,code:"AUTH_REQUIRED"};
  const r=await fetch(SUPABASE_URL+"/auth/v1/user",{
    headers:{apikey:PUBLISHABLE_KEY,authorization:auth,accept:"application/json"}
  });
  if(!r.ok)throw{status:401,code:"INVALID_SESSION"};
  const user=await r.json();
  if(!user?.id)throw{status:401,code:"INVALID_SESSION"};
  return{user,authorization:auth};
}
async function userRpc(name,payload,authorization){
  const r=await fetch(SUPABASE_URL+"/rest/v1/rpc/"+name,{
    method:"POST",
    headers:{
      apikey:PUBLISHABLE_KEY,
      authorization,
      "content-type":"application/json",
      accept:"application/json"
    },
    body:JSON.stringify(payload||{})
  });
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR",details:x.data};
  if(x.data?.ok===false)throw{
    status:Number(x.data.status)||400,
    code:x.data.code||"REQUEST_REJECTED",
    details:x.data
  };
  return x.data;
}
function serviceHeaders(){
  const h={apikey:SECRET_KEY,"content-type":"application/json",accept:"application/json"};
  if(SECRET_KEY&&!SECRET_KEY.startsWith("sb_secret_"))h.authorization="Bearer "+SECRET_KEY;
  return h;
}
async function serviceRpc(name,payload){
  const r=await fetch(SUPABASE_URL+"/rest/v1/rpc/"+name,{
    method:"POST",headers:serviceHeaders(),body:JSON.stringify(payload||{})
  });
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR",details:x.data};
  if(x.data?.ok===false)throw{
    status:Number(x.data.status)||400,
    code:x.data.code||"REQUEST_REJECTED",
    details:x.data
  };
  return x.data;
}
function randomHex(bytes=16){
  const a=new Uint8Array(bytes);crypto.getRandomValues(a);
  return[...a].map(x=>x.toString(16).padStart(2,"0")).join("");
}
function randomSecret(bytes=32){
  const a=new Uint8Array(bytes);crypto.getRandomValues(a);
  let s="";for(const b of a)s+=String.fromCharCode(b);
  return "tr_scim_secret_"+btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
async function sha256(value){
  const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(String(value||"")));
  return[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
function endpoints(tenantKey){
  const root=CANONICAL_APP_ORIGIN+"/scim/v2";
  const base=tenantKey?root+"/"+encodeURIComponent(String(tenantKey)):root;
  return{
    endpoint:base,
    scimBaseUrl:base,
    serviceProviderConfigUrl:base+"/ServiceProviderConfig",
    usersUrl:base+"/Users"
  };
}
function decorate(data){
  const cfg=data?.config||{};
  const counts=data?.counts||{};
  const credentials=Array.isArray(data?.credentials)?data.credentials:[];
  return{
    ...data,
    configured:Boolean(data?.configured),
    status:cfg.status||data?.status||(data?.configured?"active":"not_configured"),
    providerKind:cfg.providerKind||data?.providerKind||null,
    defaultRole:cfg.defaultRole||data?.defaultRole||"verifier",
    rateLimitPerMinute:Number(cfg.rateLimitPerMinute||data?.rateLimitPerMinute||300),
    lastSyncAt:cfg.lastSyncAt||data?.lastSyncAt||null,
    lastError:cfg.lastError||data?.lastError||null,
    tenantKey:data?.tenantKey||cfg.tenantKey||null,
    credentials,
    users:{
      total:Number(counts.users??data?.users?.total??0),
      active:Number(counts.activeUsers??data?.users?.active??0),
      inactive:Math.max(0,Number(counts.users??0)-Number(counts.activeUsers??0))
    },
    ...endpoints(data?.tenantKey||cfg.tenantKey||null)
  };
}

Deno.serve(async req=>{
  try{
    if(req.method==="OPTIONS"){
      if((req.headers.get("origin")||"")!==CANONICAL_APP_ORIGIN)
        return out(req,{error:{code:"CORS_ORIGIN_DENIED"}},403);
      return new Response(null,{status:204,headers:cors(req)});
    }
    if(req.method!=="POST")return out(req,{error:{code:"METHOD_NOT_ALLOWED"}},405);
    if(!SUPABASE_URL||!PUBLISHABLE_KEY||!SECRET_KEY||!CANONICAL_APP_ORIGIN)
      throw{status:503,code:"SCIM_ADMIN_NOT_CONFIGURED"};
    if((req.headers.get("origin")||"")!==CANONICAL_APP_ORIGIN)
      throw{status:403,code:"CORS_ORIGIN_DENIED"};

    const {authorization}=await userSession(req);
    const input=await body(req);
    const action=String(input.action||"");
    const orgId=String(input.orgId||"").trim();
    if(!orgId)throw{status:400,code:"ORGANIZATION_ID_REQUIRED"};

    const status=await userRpc("trustrelay_scim_admin_status_v14",{p_org_id:orgId},authorization);

    if(action==="status")return out(req,decorate(status));

    if(["create_credential","rotate_credential","enable","rotate"].includes(action)){
      const role=String(input.defaultRole||status?.config?.defaultRole||"verifier");
      if(!["compliance","verifier","developer","auditor"].includes(role))
        throw{status:400,code:"SCIM_DEFAULT_ROLE_INVALID"};

      const days=Math.max(31,Math.min(1095,Number(input.expirationDays||365)||365));
      const expiresAt=new Date(Date.now()+days*86400000).toISOString();
      const clientId="tr_scim_"+randomHex(16);
      const clientSecret=randomSecret(32);
      const label=String(
        input.label||(["rotate_credential","rotate"].includes(action)?"Rotation":"Primary")
      ).trim().slice(0,80)||"Primary";

      const result=await serviceRpc("trustrelay_scim_store_credential_v14",{
        p_org_id:orgId,
        p_actor_account_id:status.actorAccountId,
        p_client_id:clientId,
        p_secret_hash:await sha256(clientSecret),
        p_secret_last_four:clientSecret.slice(-4),
        p_label:label,
        p_default_role:role,
        p_expires_at:expiresAt
      });
      const fresh=await userRpc("trustrelay_scim_admin_status_v14",{p_org_id:orgId},authorization);
      return out(req,{
        ...decorate(fresh),
        credential:{
          id:result.credentialId,
          clientId,
          clientSecret,
          bearerToken:clientSecret,
          expiresAt,
          label,
          secretLastFour:clientSecret.slice(-4),
          shownOnce:true
        },
        token:clientSecret,
        tokenExpiresAt:expiresAt
      },201);
    }

    if(action==="revoke_credential"){
      const credentialId=String(input.credentialId||"").trim();
      if(!credentialId)throw{status:400,code:"SCIM_CREDENTIAL_ID_REQUIRED"};
      await serviceRpc("trustrelay_scim_revoke_credential_v14",{
        p_org_id:orgId,
        p_actor_account_id:status.actorAccountId,
        p_credential_id:credentialId
      });
      const fresh=await userRpc("trustrelay_scim_admin_status_v14",{p_org_id:orgId},authorization);
      return out(req,decorate(fresh));
    }

    if(action==="policy"){
      const role=String(input.defaultRole||status?.config?.defaultRole||"verifier");
      if(!["compliance","verifier","developer","auditor"].includes(role))
        throw{status:400,code:"SCIM_DEFAULT_ROLE_INVALID"};
      await serviceRpc("trustrelay_scim_set_policy_v14",{
        p_org_id:orgId,
        p_actor_account_id:status.actorAccountId,
        p_default_role:role,
        p_allow_static_bearer:true,
        p_group_sync_enabled:false
      });
      const fresh=await userRpc("trustrelay_scim_admin_status_v14",{p_org_id:orgId},authorization);
      return out(req,decorate(fresh));
    }

    if(action==="disable"){
      await serviceRpc("trustrelay_scim_disable_v14",{
        p_org_id:orgId,p_actor_account_id:status.actorAccountId
      });
      const fresh=await userRpc("trustrelay_scim_admin_status_v14",{p_org_id:orgId},authorization);
      return out(req,decorate(fresh));
    }

    throw{status:400,code:"ACTION_INVALID"};
  }catch(e){
    return out(req,{error:{
      code:e?.code||"SCIM_ADMIN_ERROR",
      details:e?.details||null
    }},Number(e?.status)||500);
  }
});
