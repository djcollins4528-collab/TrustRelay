const URL=(Deno.env.get("SUPABASE_URL")||"").replace(/\/$/,"");
const CANONICAL_APP_ORIGIN=URL.includes("msfrbsnihylfynrtdgxe")?"https://trustrelay-production.onrender.com":URL.includes("kdvroylluosshcjmfbfq")?"https://trustrelay-staging.onrender.com":"";
const APP_ORIGIN=(Deno.env.get("TRUSTRELAY_APP_ORIGIN")||CANONICAL_APP_ORIGIN).replace(/\/$/,"");
const SAML_ENABLED=/^(1|true|yes)$/i.test(Deno.env.get("TRUSTRELAY_SAML_ENABLED")||"false");

function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function secretKey(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function publishableKey(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||""}
function adminHeaders(){
  const k=secretKey();
  const h={apikey:k,"content-type":"application/json",accept:"application/json"};
  if(k&&!k.startsWith("sb_secret_"))h.authorization="Bearer "+k;
  return h
}
function corsHeaders(req){
  const origin=req.headers.get("origin")||"";
  if(!origin||!APP_ORIGIN||origin!==APP_ORIGIN)return{};
  return {"access-control-allow-origin":origin,"access-control-allow-methods":"POST, OPTIONS","access-control-allow-headers":"authorization, apikey, content-type","access-control-max-age":"86400",vary:"Origin"};
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
  const authorization=req.headers.get("authorization")||"";
  if(!/^Bearer\s+\S+/i.test(authorization))throw{status:401,code:"AUTH_REQUIRED"};
  const r=await fetch(URL+"/auth/v1/user",{headers:{apikey:publishableKey(),authorization,accept:"application/json"}});
  if(!r.ok)throw{status:401,code:"INVALID_SESSION"};
  const user=await r.json();
  if(!user?.id)throw{status:401,code:"INVALID_SESSION"};
  return{user,authorization}
}
async function rpcUser(name,payload,authorization){
  const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:{apikey:publishableKey(),authorization,"content-type":"application/json",accept:"application/json"},body:JSON.stringify(payload||{})});
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR",details:x.data};
  if(x.data?.ok===false)throw{status:Number(x.data?.status)||400,code:x.data?.code||"REQUEST_REJECTED",details:x.data};
  return x.data
}
async function rpcAdmin(name,payload){
  const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:adminHeaders(),body:JSON.stringify(payload||{})});
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR",details:x.data};
  if(x.data?.ok===false)throw{status:Number(x.data?.status)||400,code:x.data?.code||"REQUEST_REJECTED",details:x.data};
  return x.data
}
async function sha256Hex(value){
  const b=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(String(value||""))));
  return [...b].map(x=>x.toString(16).padStart(2,"0")).join("")
}
function randomHex(bytes=24){
  const b=crypto.getRandomValues(new Uint8Array(bytes));
  return [...b].map(x=>x.toString(16).padStart(2,"0")).join("")
}
function equalHex(a,b){
  if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;
  let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);
  return diff===0
}
function normalizeTxtData(value){
  const raw=String(value||"").trim();
  const chunks=[...raw.matchAll(/"((?:\\.|[^"])*)"/g)].map(m=>m[1].replace(/\\(["\\])/g,"$1"));
  return chunks.length?chunks.join(""):raw
}
async function lookupTxt(name){
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),5000);
  try{
    const url="https://cloudflare-dns.com/dns-query?name="+encodeURIComponent(name)+"&type=TXT";
    const r=await fetch(url,{headers:{accept:"application/dns-json"},signal:controller.signal});
    if(!r.ok)throw{status:502,code:"DNS_VERIFICATION_PROVIDER_ERROR",details:{providerStatus:r.status}};
    const data=await r.json();
    if(Number(data?.Status)!==0)return[];
    return (Array.isArray(data?.Answer)?data.Answer:[])
      .filter(x=>Number(x?.type)===16)
      .map(x=>normalizeTxtData(x?.data))
      .filter(Boolean)
  }catch(e){
    if(e?.name==="AbortError")throw{status:504,code:"DNS_VERIFICATION_TIMEOUT"};
    throw e
  }finally{clearTimeout(timer)}
}
async function discoveryRateLimit(req){
  const forwarded=(req.headers.get("cf-connecting-ip")||req.headers.get("x-forwarded-for")||"unknown").split(",")[0].trim();
  const key=(await sha256Hex(forwarded)).slice(0,32);
  const x=await rpcAdmin("consume_rate_limit_v05",{p_bucket_key:"sso-discovery:"+key,p_limit:20,p_window_seconds:60});
  const row=Array.isArray(x)?x[0]:x;
  if(row?.allowed===false)throw{status:429,code:"RATE_LIMITED",details:{resetAt:row.reset_at||null}};
}
function normalizeEmail(value){
  const email=String(value||"").trim().toLowerCase();
  if(email.length<3||email.length>320||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))throw{status:400,code:"EMAIL_INVALID"};
  return email
}
function normalizeDomains(input){
  if(!Array.isArray(input))return[];
  const blocked=new Set(["gmail.com","yahoo.com","outlook.com","hotmail.com","icloud.com","aol.com","proton.me","protonmail.com"]);
  const result=[...new Set(input.map(x=>String(x||"").trim().toLowerCase()).filter(Boolean))];
  if(!result.length||result.length>20)throw{status:400,code:"SSO_DOMAIN_COUNT_INVALID"};
  for(const d of result){
    if(!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d))throw{status:400,code:"SSO_DOMAIN_INVALID"};
    if(blocked.has(d))throw{status:400,code:"SSO_PERSONAL_DOMAIN_NOT_ALLOWED"};
  }
  return result
}
function providerIdentifier(orgId,brand){
  const suffix=String(orgId||"").replace(/^org_/,"").replace(/[^a-z0-9]/gi,"").toLowerCase().slice(0,16);
  if(!suffix)throw{status:400,code:"ORGANIZATION_ID_INVALID"};
  return "custom:tr-"+(brand==="microsoft_entra"?"entra":"okta")+"-"+suffix
}
function providerKind(brand){return brand==="microsoft_entra"?"entra":"okta"}
function displayName(brand){return brand==="microsoft_entra"?"Microsoft Entra ID":"Okta"}
function validateOktaIssuer(value){
  let u;try{u=new URL(String(value||""))}catch{throw{status:400,code:"OKTA_ISSUER_INVALID"}}
  const host=u.hostname.toLowerCase();
  if(u.protocol!=="https:"||u.username||u.password||u.port||u.hash||u.search)throw{status:400,code:"OKTA_ISSUER_INVALID"};
  if(!(host.endsWith(".okta.com")||host.endsWith(".oktapreview.com")||host.endsWith(".okta-emea.com")))throw{status:400,code:"OKTA_ISSUER_HOST_NOT_ALLOWED"};
  return u.toString().replace(/\/$/,"")
}
function entraIssuer(tenantId){
  const t=String(tenantId||"").trim().toLowerCase();
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(t))throw{status:400,code:"ENTRA_TENANT_ID_INVALID"};
  return "https://login.microsoftonline.com/"+t+"/v2.0"
}
function validateSamlMetadataUrl(value,brand){
  let u;try{u=new URL(String(value||""))}catch{throw{status:400,code:"SAML_METADATA_URL_INVALID"}}
  const host=u.hostname.toLowerCase();
  if(u.protocol!=="https:"||u.username||u.password||u.port||u.hash)throw{status:400,code:"SAML_METADATA_URL_INVALID"};
  if(brand==="microsoft_entra"&&host!=="login.microsoftonline.com")throw{status:400,code:"ENTRA_METADATA_HOST_NOT_ALLOWED"};
  if(brand==="okta"&&!(host.endsWith(".okta.com")||host.endsWith(".oktapreview.com")||host.endsWith(".okta-emea.com")))throw{status:400,code:"OKTA_METADATA_HOST_NOT_ALLOWED"};
  return u.toString()
}
async function authAdmin(path,method="GET",body){
  if(!secretKey())throw{status:503,code:"SSO_CONTROL_PLANE_NOT_CONFIGURED"};
  const r=await fetch(URL+"/auth/v1/admin/"+path,{method,headers:adminHeaders(),body:body===undefined?undefined:JSON.stringify(body)});
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||502,code:x.data?.error_code||x.data?.code||"SSO_PROVIDER_ADMIN_ERROR",details:{providerStatus:x.status,providerCode:x.data?.error_code||x.data?.code||null}};
  return x.data
}
async function customProviderUpsert(identifier,payload){
  try{return await authAdmin("custom-providers/"+encodeURIComponent(identifier),"PUT",payload)}
  catch(e){if(Number(e?.status)!==404)throw e}
  return await authAdmin("custom-providers","POST",{provider_type:"oidc",identifier,...payload})
}
async function customProviderDisable(identifier){
  if(!String(identifier||"").startsWith("custom:"))return;
  try{await authAdmin("custom-providers/"+encodeURIComponent(identifier),"PUT",{enabled:false})}
  catch(e){if(Number(e?.status)!==404)throw e}
}
async function samlProviderUpsert(existingId,metadataUrl,domains,resourceId){
  const attribute_mapping={keys:{
    email:{names:["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress","mail","email"]},
    name:{names:["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name","displayName","name"]}
  }};
  if(existingId)return await authAdmin("sso/providers/"+encodeURIComponent(existingId),"PUT",{metadata_url:metadataUrl,domains,attribute_mapping,disabled:false});
  return await authAdmin("sso/providers","POST",{type:"saml",metadata_url:metadataUrl,domains,resource_id:resourceId,attribute_mapping})
}
async function samlProviderDisable(id){
  if(!id)return;
  try{await authAdmin("sso/providers/"+encodeURIComponent(id),"PUT",{disabled:true})}
  catch(e){if(Number(e?.status)!==404)throw e}
}
async function requireManage(orgId,authorization){
  const p=await rpcUser("trustrelay_my_org_permissions_v09",{p_org_id:orgId},authorization);
  if(p?.permissions?.["organization.manage"]!==true)throw{status:403,code:"ORGANIZATION_PERMISSION_DENIED"};
  const cfg=await rpcUser("trustrelay_sso_config_v13",{p_org_id:orgId},authorization);
  return{permissions:p,config:cfg}
}
async function prepareDomainChallenges(orgId,actorAccountId){
  const state=await rpcAdmin("trustrelay_sso_domain_state_v13",{p_org_id:orgId});
  const challenges=[];
  for(const row of Array.isArray(state?.domains)?state.domains:[]){
    if(row?.verificationStatus==="verified")continue;
    const token=randomHex(24);
    const recordName="_trustrelay."+String(row.domain||"");
    const recordValue="trustrelay-verification="+token;
    const tokenHash=await sha256Hex(recordValue);
    await rpcAdmin("trustrelay_set_sso_domain_challenge_v13",{
      p_org_id:orgId,p_actor_account_id:actorAccountId,p_domain:row.domain,p_token_hash:tokenHash
    });
    challenges.push({domain:row.domain,recordName,recordType:"TXT",recordValue})
  }
  return challenges
}
async function verifyDomains(orgId,actorAccountId){
  const state=await rpcAdmin("trustrelay_sso_domain_state_v13",{p_org_id:orgId});
  const verified=[],pending=[];
  for(const row of Array.isArray(state?.domains)?state.domains:[]){
    if(row?.verificationStatus==="verified"){verified.push(row.domain);continue}
    if(!row?.tokenHash){pending.push({domain:row.domain,reason:"challenge_required"});continue}
    const values=await lookupTxt("_trustrelay."+String(row.domain||""));
    let matched=false;
    for(const value of values){
      const hash=await sha256Hex(value);
      if(equalHex(hash,String(row.tokenHash))){matched=true;break}
    }
    if(matched){
      await rpcAdmin("trustrelay_mark_sso_domain_verified_v13",{
        p_org_id:orgId,p_actor_account_id:actorAccountId,p_domain:row.domain
      });
      verified.push(row.domain)
    }else pending.push({domain:row.domain,reason:"dns_record_not_found"})
  }
  return{verified,pending,allVerified:pending.length===0&&verified.length>0}
}
async function saveProvider({orgId,authorization,actorAccountId,protocol,brand,identifier,samlProviderId,issuer,metadataUrl,clientId,domains,jitEnabled,jitDefaultRole}){
  await rpcAdmin("trustrelay_store_sso_provider_v13",{
    p_org_id:orgId,p_actor_account_id:actorAccountId,p_protocol:protocol,p_provider_kind:providerKind(brand),
    p_provider_identifier:identifier||null,p_saml_provider_id:samlProviderId||null,p_issuer:issuer||null,
    p_metadata_url:metadataUrl||null,p_client_id:clientId||null,p_domains:domains
  });
  const challenges=await prepareDomainChallenges(orgId,actorAccountId);
  const policy=await rpcUser("trustrelay_set_sso_policy_v13",{
    p_org_id:orgId,p_enforcement_mode:"optional",p_jit_enabled:Boolean(jitEnabled),
    p_default_role:String(jitDefaultRole||"verifier"),p_break_glass_enabled:true
  },authorization);
  return{policy,challenges}
}

Deno.serve(async req=>{
  try{
    if(req.method==="OPTIONS"){
      const origin=req.headers.get("origin")||"";
      if(!APP_ORIGIN||origin!==APP_ORIGIN)return out({error:{code:"CORS_ORIGIN_DENIED"}},403,req);
      return new Response(null,{status:204,headers:corsHeaders(req)})
    }
    if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405,req);
    if(!URL||!publishableKey()||!secretKey())throw{status:503,code:"SSO_CONTROL_PLANE_NOT_CONFIGURED"};
    const input=await jsonBody(req);
    const action=String(input.action||"");

    if(action==="discover"){
      await discoveryRateLimit(req);
      const email=normalizeEmail(input.email);
      const d=await rpcAdmin("trustrelay_sso_discover_v13",{p_email:email});
      if(!d?.configured)return out({ssoAvailable:false},200,req);
      const id=d.protocol==="saml"?d.ssoProviderId:d.providerIdentifier;
      return out({ssoAvailable:true,protocol:d.protocol,providerBrand:d.providerKind,providerIdentifier:id,enforcementRequired:d.enforcementMode==="required"},200,req)
    }

    const {authorization}=await userFrom(req);
    const orgId=String(input.orgId||"").trim();
    if(!orgId)throw{status:400,code:"ORGANIZATION_ID_REQUIRED"};
    const managed=await requireManage(orgId,authorization);
    const current=managed.config||{};
    const actorAccountId=String(current.actorAccountId||"");
    if(!actorAccountId)throw{status:403,code:"ORGANIZATION_PERMISSION_DENIED"};

    if(action==="status"){
      return out({...current,capabilities:{oidc:true,saml:SAML_ENABLED,customOidcProviderLimitOnCurrentFreePlan:3},callbackUrl:URL+"/auth/v1/callback",samlMetadataUrl:URL+"/auth/v1/sso/saml/metadata",samlAcsUrl:URL+"/auth/v1/sso/saml/acs"},200,req)
    }

    if(action==="domain_challenges"){
      if(!current?.configured)throw{status:404,code:"SSO_NOT_CONFIGURED"};
      const challenges=await prepareDomainChallenges(orgId,actorAccountId);
      return out({challenges},200,req)
    }

    if(action==="verify_domains"){
      if(!current?.configured)throw{status:404,code:"SSO_NOT_CONFIGURED"};
      const result=await verifyDomains(orgId,actorAccountId);
      const config=await rpcUser("trustrelay_sso_config_v13",{p_org_id:orgId},authorization);
      return out({...result,config},200,req)
    }

    if(action==="configure_oidc"){
      const brand=String(input.providerBrand||"");
      if(!["microsoft_entra","okta"].includes(brand))throw{status:400,code:"SSO_PROVIDER_INVALID"};
      const domains=normalizeDomains(input.domains);
      const clientId=String(input.clientId||"").trim();
      const clientSecret=String(input.clientSecret||"");
      if(clientId.length<3||clientId.length>512)throw{status:400,code:"SSO_CLIENT_ID_INVALID"};
      if(clientSecret.length<8||clientSecret.length>4096)throw{status:400,code:"SSO_CLIENT_SECRET_INVALID"};
      const issuer=brand==="microsoft_entra"?entraIssuer(input.tenantId):validateOktaIssuer(input.issuerUrl);
      const identifier=providerIdentifier(orgId,brand);
      const provider=await customProviderUpsert(identifier,{
        name:"TrustRelay - "+displayName(brand),client_id:clientId,client_secret:clientSecret,
        issuer,scopes:["openid","profile","email"],pkce_enabled:true,email_optional:false,enabled:true
      });
      let saved;
      try{
        saved=await saveProvider({orgId,authorization,actorAccountId,protocol:"oidc",brand,identifier,samlProviderId:null,issuer,metadataUrl:null,clientId,domains,jitEnabled:input.jitEnabled,jitDefaultRole:input.jitDefaultRole})
      }catch(e){await customProviderDisable(identifier).catch(()=>{});throw e}
      if(current?.configured&&current?.protocol==="oidc"&&current?.providerIdentifier&&current.providerIdentifier!==identifier)await customProviderDisable(current.providerIdentifier).catch(()=>{});
      return out({configured:true,protocol:"oidc",providerBrand:brand,providerIdentifier:identifier,callbackUrl:URL+"/auth/v1/callback",issuer,domains,domainChallenges:saved?.challenges||[],providerCreated:Boolean(provider)},201,req)
    }

    if(action==="configure_saml"){
      if(!SAML_ENABLED)throw{status:409,code:"SAML_PLAN_UPGRADE_REQUIRED",details:{metadataUrl:URL+"/auth/v1/sso/saml/metadata",acsUrl:URL+"/auth/v1/sso/saml/acs"}};
      const brand=String(input.providerBrand||"");
      if(!["microsoft_entra","okta"].includes(brand))throw{status:400,code:"SSO_PROVIDER_INVALID"};
      const domains=normalizeDomains(input.domains);
      const metadataUrl=validateSamlMetadataUrl(input.metadataUrl,brand);
      const existingId=current?.configured&&current?.protocol==="saml"?current.ssoProviderId:null;
      const provider=await samlProviderUpsert(existingId,metadataUrl,domains,"trustrelay-"+providerKind(brand)+"-"+String(orgId).replace(/^org_/,"").slice(0,16));
      const providerId=String(provider?.id||existingId||"");
      if(!providerId)throw{status:502,code:"SAML_PROVIDER_ID_MISSING"};
      const saved=await saveProvider({orgId,authorization,actorAccountId,protocol:"saml",brand,identifier:null,samlProviderId:providerId,issuer:null,metadataUrl,clientId:null,domains,jitEnabled:input.jitEnabled,jitDefaultRole:input.jitDefaultRole});
      return out({configured:true,protocol:"saml",providerBrand:brand,providerIdentifier:providerId,metadataUrl:URL+"/auth/v1/sso/saml/metadata",acsUrl:URL+"/auth/v1/sso/saml/acs",domains,domainChallenges:saved?.challenges||[]},201,req)
    }

    if(action==="disable"){
      if(!current?.configured)throw{status:404,code:"SSO_NOT_CONFIGURED"};
      if(current.protocol==="oidc")await customProviderDisable(current.providerIdentifier);
      else if(current.protocol==="saml")await samlProviderDisable(current.ssoProviderId);
      await rpcUser("trustrelay_disable_sso_v13",{p_org_id:orgId},authorization);
      return out({disabled:true},200,req)
    }

    throw{status:400,code:"ACTION_INVALID"}
  }catch(e){
    return out({error:{code:e?.code||"INTERNAL_ERROR",details:e?.details||null}},Number(e?.status)||500,req)
  }
});