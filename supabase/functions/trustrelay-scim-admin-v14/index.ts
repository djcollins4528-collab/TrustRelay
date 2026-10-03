const SUPABASE_URL=(Deno.env.get("SUPABASE_URL")||"").replace(/\/$/,"");
const CANONICAL_APP_ORIGIN=SUPABASE_URL.includes("msfrbsnihylfynrtdgxe")
  ?"https://trustrelay-production.onrender.com"
  :SUPABASE_URL.includes("kdvroylluosshcjmfbfq")
    ?"https://trustrelay-staging.onrender.com":"";
function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function publishableKey(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||""}
const PUBLISHABLE_KEY=publishableKey();

function cors(req){
  const origin=req.headers.get("origin")||"";
  if(!origin||origin!==CANONICAL_APP_ORIGIN)return {};
  return {
    "access-control-allow-origin":origin,
    "access-control-allow-methods":"POST, OPTIONS",
    "access-control-allow-headers":"authorization, apikey, content-type",
    "access-control-max-age":"86400","vary":"Origin"
  };
}
function out(req,data,status=200){
  return Response.json(data,{status,headers:{
    "cache-control":"no-store","x-content-type-options":"nosniff",...cors(req)
  }});
}
async function parse(r){
  const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}
  return{ok:r.ok,status:r.status,data:d,text:t}
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
  return {user,authorization:auth};
}
async function userRpc(name,payload,authorization){
  const r=await fetch(SUPABASE_URL+"/rest/v1/rpc/"+name,{
    method:"POST",
    headers:{
      apikey:PUBLISHABLE_KEY,authorization,
      "content-type":"application/json",accept:"application/json"
    },
    body:JSON.stringify(payload||{})
  });
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR"};
  if(x.data?.ok===false)throw{
    status:Number(x.data.status)||400,
    code:x.data.code||"REQUEST_REJECTED",
    details:x.data
  };
  return x.data;
}
function endpointFor(tenantKey){
  return tenantKey&&CANONICAL_APP_ORIGIN
    ?CANONICAL_APP_ORIGIN+"/scim/v2/"+encodeURIComponent(String(tenantKey))
    :null;
}
function decorate(data){
  const endpoint=endpointFor(data?.tenantKey);
  const counts=data?.users||{};
  return {
    ...data,
    totalUsers:Number(data?.totalUsers??counts.total??0),
    activeUsers:Number(data?.activeUsers??counts.active??0),
    inactiveUsers:Number(data?.inactiveUsers??counts.inactive??0),
    endpoint,
    scimBaseUrl:endpoint,
    serviceProviderConfigUrl:endpoint?endpoint+"/ServiceProviderConfig":null
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
    if(!SUPABASE_URL||!PUBLISHABLE_KEY||!CANONICAL_APP_ORIGIN)
      throw{status:503,code:"SCIM_ADMIN_NOT_CONFIGURED"};
    if((req.headers.get("origin")||"")!==CANONICAL_APP_ORIGIN)
      throw{status:403,code:"CORS_ORIGIN_DENIED"};

    const {authorization}=await userSession(req);
    const input=await body(req);
    const action=String(input.action||"");
    const orgId=String(input.orgId||"").trim();
    if(!orgId)throw{status:400,code:"ORGANIZATION_ID_REQUIRED"};

    if(action==="status"){
      return out(req,decorate(await userRpc(
        "trustrelay_scim_admin_status_v14",{p_org_id:orgId},authorization
      )));
    }

    if(action==="enable"){
      const role=String(input.defaultRole||"verifier");
      const result=await userRpc("trustrelay_scim_enable_v14",{
        p_org_id:orgId,p_default_role:role,p_token_ttl_days:180
      },authorization);
      return out(req,decorate(result),201);
    }

    if(action==="rotate"){
      const result=await userRpc("trustrelay_scim_rotate_token_v14",{
        p_org_id:orgId,p_token_ttl_days:180
      },authorization);
      const status=await userRpc("trustrelay_scim_admin_status_v14",{
        p_org_id:orgId
      },authorization);
      return out(req,decorate({...status,...result}));
    }

    if(action==="policy"){
      const status=String(input.status||"enabled");
      const role=String(input.defaultRole||"verifier");
      const result=await userRpc("trustrelay_scim_set_policy_v14",{
        p_org_id:orgId,p_status:status,p_default_role:role
      },authorization);
      const current=await userRpc("trustrelay_scim_admin_status_v14",{
        p_org_id:orgId
      },authorization);
      return out(req,decorate({...current,...result}));
    }

    throw{status:400,code:"ACTION_INVALID"};
  }catch(e){
    return out(req,{error:{
      code:e?.code||"SCIM_ADMIN_ERROR",
      details:e?.details||null
    }},Number(e?.status)||500);
  }
});