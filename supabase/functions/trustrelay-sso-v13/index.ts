const URL=(Deno.env.get("SUPABASE_URL")||"").replace(/\/$/,"");
const CANONICAL_APP_ORIGIN=URL.includes("msfrbsnihylfynrtdgxe")?"https://trustrelay-production.onrender.com":URL.includes("kdvroylluosshcjmfbfq")?"https://trustrelay-staging.onrender.com":"";
function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function secretKey(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function publishableKey(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||""}
function adminHeaders(){
  const k=secretKey();
  const h={apikey:k,"content-type":"application/json",accept:"application/json"};
  if(k&&!k.startsWith("sb_secret_"))h.authorization="Bearer "+k;
  return h;
}
function corsHeaders(req){
  const origin=req.headers.get("origin")||"";
  if(!origin||!CANONICAL_APP_ORIGIN||origin!==CANONICAL_APP_ORIGIN)return{};
  return {
    "access-control-allow-origin":origin,
    "access-control-allow-methods":"POST, OPTIONS",
    "access-control-allow-headers":"authorization, apikey, content-type",
    "access-control-max-age":"86400","vary":"Origin"
  };
}
function out(data,status=200,req=null){return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff",...corsHeaders(req)}})}
async function parse(r){const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}return{ok:r.ok,status:r.status,data:d,text:t}}
async function jsonBody(req,max=32768){
  const n=Number(req.headers.get("content-length")||0);
  if(Number.isFinite(n)&&n>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};
  const raw=await req.text();
  if(new TextEncoder().encode(raw).byteLength>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};
  try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON"}}
}
async function userFrom(req){
  const auth=req.headers.get("authorization")||"";
  if(!/^Bearer\s+\S+/i.test(auth))throw{status:401,code:"AUTH_REQUIRED"};
  const r=await fetch(URL+"/auth/v1/user",{headers:{apikey:publishableKey(),authorization:auth,accept:"application/json"}});
  if(!r.ok)throw{status:401,code:"INVALID_SESSION"};
  const user=await r.json();
  if(!user?.id)throw{status:401,code:"INVALID_SESSION"};
  return {user,authorization:auth};
}
async function rpc(name,payload,authorization){
  const r=await fetch(URL+"/rest/v1/rpc/"+name,{
    method:"POST",
    headers:{apikey:publishableKey(),authorization,"content-type":"application/json",accept:"application/json"},
    body:JSON.stringify(payload||{})
  });
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR"};
  if(x.data?.ok===false)throw{status:Number(x.data?.status)||400,code:x.data?.code||"REQUEST_REJECTED",details:x.data};
  return x.data;
}
function normalizeDomains(input){
  if(!Array.isArray(input))return[];
  const blocked=new Set(["gmail.com","yahoo.com","outlook.com","hotmail.com","icloud.com","aol.com","proton.me","protonmail.com"]);
  return [...new Set(input.map(x=>String(x||"").trim().toLowerCase()).filter(x=>
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(x)&&!blocked.has(x)
  ))].slice(0,20);
}
function providerIdentifier(orgId,brand){
  const suffix=String(orgId||"").replace(/^org_/,"").replace(/[^a-z0-9]/gi,"").toLowerCase().slice(0,16);
  if(!suffix)throw{status:400,code:"ORGANIZATION_ID_INVALID"};
  return "custom:tr-"+(brand==="microsoft_entra"?"entra":"okta")+"-"+suffix;
}
function validateOktaIssuer(value){
  let u;try{u=new URL(String(value||""))}catch{throw{status:400,code:"OKTA_ISSUER_INVALID"}}
  const host=u.hostname.toLowerCase();
  if(u.protocol!=="https:"||u.username||u.password||u.port)throw{status:400,code:"OKTA_ISSUER_INVALID"};
  const ok=host.endsWith(".okta.com")||host.endsWith(".oktapreview.com")||host.endsWith(".okta-emea.com");
  if(!ok)throw{status:400,code:"OKTA_ISSUER_HOST_NOT_ALLOWED"};
  u.hash="";u.search="";
  return u.toString().replace(/\/$/,"");
}
function entraIssuer(tenantId){
  const t=String(tenantId||"").trim().toLowerCase();
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(t))
    throw{status:400,code:"ENTRA_TENANT_ID_INVALID"};
  return "https://login.microsoftonline.com/"+t+"/v2.0";
}
async function customProviderUpsert(identifier,payload){
  const endpoint=URL+"/auth/v1/admin/custom-providers/"+encodeURIComponent(identifier);
  let r=await fetch(endpoint,{method:"PUT",headers:adminHeaders(),body:JSON.stringify(payload)});
  if(r.status===404){
    r=await fetch(URL+"/auth/v1/admin/custom-providers",{method:"POST",headers:adminHeaders(),body:JSON.stringify({provider_type:"oidc",identifier,...payload})});
  }
  const x=await parse(r);
  if(!x.ok)throw{status:502,code:"SSO_PROVIDER_CONFIG_FAILED",details:{providerStatus:x.status,providerCode:x.data?.code||x.data?.error_code||null}};
  return x.data;
}
async function customProviderDisable(identifier){
  if(!identifier?.startsWith("custom:"))return;
  const r=await fetch(URL+"/auth/v1/admin/custom-providers/"+encodeURIComponent(identifier),{
    method:"PUT",headers:adminHeaders(),body:JSON.stringify({enabled:false})
  });
  if(!r.ok&&r.status!==404){
    const x=await parse(r);throw{status:502,code:"SSO_PROVIDER_DISABLE_FAILED",details:{providerStatus:x.status}};
  }
}
async function samlCreate(metadataUrl,domains,resourceId){
  const enabled=/^(1|true|yes)$/i.test(Deno.env.get("TRUSTRELAY_SAML_ENABLED")||"false");
  if(!enabled)throw{status:503,code:"SAML_PLAN_UPGRADE_REQUIRED"};
  let u;try{u=new URL(metadataUrl)}catch{throw{status:400,code:"SAML_METADATA_URL_INVALID"}}
  if(u.protocol!=="https:"||u.username||u.password)throw{status:400,code:"SAML_METADATA_URL_INVALID"};
  const r=await fetch(URL+"/auth/v1/admin/sso/providers",{
    method:"POST",headers:adminHeaders(),
    body:JSON.stringify({type:"saml",metadata_url:u.toString(),domains,resource_id:resourceId})
  });
  const x=await parse(r);
  if(!x.ok)throw{status:502,code:"SAML_PROVIDER_CONFIG_FAILED",details:{providerStatus:x.status,providerCode:x.data?.code||null}};
  return x.data;
}

Deno.serve(async req=>{
  try{
    if(req.method==="OPTIONS"){
      const origin=req.headers.get("origin")||"";
      if(!CANONICAL_APP_ORIGIN||origin!==CANONICAL_APP_ORIGIN)return out({error:{code:"CORS_ORIGIN_DENIED"}},403,req);
      return new Response(null,{status:204,headers:corsHeaders(req)});
    }
    if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405,req);
    if(!secretKey()||!publishableKey()||!URL)throw{status:503,code:"SSO_CONTROL_PLANE_NOT_CONFIGURED"};

    const {authorization}=await userFrom(req);
    const input=await jsonBody(req);
    const action=String(input.action||"");
    const orgId=String(input.orgId||"").trim();
    if(!orgId)throw{status:400,code:"ORGANIZATION_ID_REQUIRED"};

    const perms=await rpc("trustrelay_my_org_permissions_v09",{p_org_id:orgId},authorization);
    if(perms?.permissions?.["organization.manage"]!==true)throw{status:403,code:"ORGANIZATION_PERMISSION_DENIED"};

    if(action==="configure_oidc"){
      const brand=String(input.providerBrand||"");
      if(!["microsoft_entra","okta"].includes(brand))throw{status:400,code:"SSO_PROVIDER_INVALID"};
      const domains=normalizeDomains(input.domains);
      if(!domains.length)throw{status:400,code:"SSO_DOMAIN_REQUIRED"};
      const clientId=String(input.clientId||"").trim();
      const clientSecret=String(input.clientSecret||"").trim();
      if(clientId.length<3||clientId.length>512)throw{status:400,code:"SSO_CLIENT_ID_INVALID"};
      if(clientSecret.length<8||clientSecret.length>4096)throw{status:400,code:"SSO_CLIENT_SECRET_INVALID"};
      const issuer=brand==="microsoft_entra"?entraIssuer(input.tenantId):validateOktaIssuer(input.issuerUrl);
      const identifier=providerIdentifier(orgId,brand);
      const displayName=brand==="microsoft_entra"?"Microsoft Entra ID":"Okta";
      const previous=await rpc("trustrelay_sso_status_v13",{p_org_id:orgId},authorization).catch(()=>({configured:false}));
      const provider=await customProviderUpsert(identifier,{
        name:"TrustRelay — "+displayName,
        client_id:clientId,
        client_secret:clientSecret,
        issuer,
        scopes:["openid","profile","email"],
        pkce_enabled:true,
        email_optional:false,
        enabled:true
      });
      try{
        await rpc("trustrelay_register_sso_connection_v13",{
          p_org_id:orgId,p_provider_brand:brand,p_protocol:"oidc",p_provider_identifier:identifier,
          p_display_name:displayName,p_issuer_url:issuer,p_metadata_url:null,p_domains:domains,
          p_jit_enabled:Boolean(input.jitEnabled),p_jit_default_role:String(input.jitDefaultRole||"verifier")
        },authorization);
      }catch(e){
        await customProviderDisable(identifier).catch(()=>{});
        throw e;
      }
      const old=previous?.connection?.providerIdentifier;
      if(old&&old!==identifier&&String(old).startsWith("custom:"))await customProviderDisable(old).catch(()=>{});
      return out({configured:true,protocol:"oidc",providerBrand:brand,providerIdentifier:identifier,
        callbackUrl:URL+"/auth/v1/callback",issuer,domains,providerCreated:Boolean(provider)},201,req);
    }

    if(action==="configure_saml"){
      const brand=String(input.providerBrand||"");
      if(!["microsoft_entra","okta"].includes(brand))throw{status:400,code:"SSO_PROVIDER_INVALID"};
      const domains=normalizeDomains(input.domains);
      if(!domains.length)throw{status:400,code:"SSO_DOMAIN_REQUIRED"};
      const metadataUrl=String(input.metadataUrl||"").trim();
      const resourceId="trustrelay-"+brand+"-"+String(orgId).replace(/^org_/,"").slice(0,16);
      const provider=await samlCreate(metadataUrl,domains,resourceId);
      const providerId=String(provider?.id||"");
      if(!providerId)throw{status:502,code:"SAML_PROVIDER_ID_MISSING"};
      await rpc("trustrelay_register_sso_connection_v13",{
        p_org_id:orgId,p_provider_brand:brand,p_protocol:"saml",p_provider_identifier:providerId,
        p_display_name:brand==="microsoft_entra"?"Microsoft Entra ID":"Okta",
        p_issuer_url:null,p_metadata_url:metadataUrl,p_domains:domains,
        p_jit_enabled:Boolean(input.jitEnabled),p_jit_default_role:String(input.jitDefaultRole||"verifier")
      },authorization);
      return out({configured:true,protocol:"saml",providerBrand:brand,providerIdentifier:providerId,
        metadataUrl:URL+"/auth/v1/sso/saml/metadata",acsUrl:URL+"/auth/v1/sso/saml/acs",domains},201,req);
    }

    if(action==="disable"){
      const current=await rpc("trustrelay_sso_status_v13",{p_org_id:orgId},authorization);
      const identifier=current?.connection?.providerIdentifier;
      await rpc("trustrelay_disable_sso_v13",{p_org_id:orgId},authorization);
      if(identifier&&String(identifier).startsWith("custom:"))await customProviderDisable(String(identifier));
      return out({disabled:true},200,req);
    }

    throw{status:400,code:"ACTION_INVALID"};
  }catch(e){
    return out({error:{code:e?.code||"INTERNAL_ERROR",details:e?.details||null}},Number(e?.status)||500,req);
  }
});