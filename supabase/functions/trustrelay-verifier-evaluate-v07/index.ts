
const URL=Deno.env.get("SUPABASE_URL")||"";
const CANONICAL_APP_ORIGIN=URL.includes("msfrbsnihylfynrtdgxe")?"https://trustrelay-production.onrender.com":URL.includes("kdvroylluosshcjmfbfq")?"https://trustrelay-staging.onrender.com":"";
const APP_ORIGIN=(Deno.env.get("TRUSTRELAY_APP_ORIGIN")||CANONICAL_APP_ORIGIN).replace(/\/$/,"");
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function pub(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||Deno.env.get("SUPABASE_ANON_KEY")||""}
function sec(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||""}
function sh(){const k=sec();const h={apikey:k,"content-type":"application/json",accept:"application/json"};if(k&&!k.startsWith("sb_secret_"))h.authorization="Bearer "+k;return h}
async function parse(r){const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}return{ok:r.ok,status:r.status,data:d}}
async function rpc(name,payload){
  const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:sh(),body:JSON.stringify(payload||{})});
  const x=await parse(r);if(!x.ok)throw{status:503,code:"DATABASE_ERROR"};return x.data;
}
async function user(req){
  const auth=req.headers.get("authorization")||"";
  if(!/^Bearer\s+\S+/i.test(auth))throw{status:401,code:"AUTH_REQUIRED"};
  const r=await fetch(URL+"/auth/v1/user",{headers:{apikey:pub(),authorization:auth,accept:"application/json"}});
  if(!r.ok)throw{status:401,code:"INVALID_SESSION"};
  const u=await r.json();if(!u?.id)throw{status:401,code:"INVALID_SESSION"};return u;
}
function corsHeaders(req){
  const origin=req?.headers?.get?.("origin")||"";
  if(!origin||!CANONICAL_APP_ORIGIN||origin!==CANONICAL_APP_ORIGIN)return{};
  return {
    "access-control-allow-origin":origin,
    "access-control-allow-methods":"POST, OPTIONS",
    "access-control-allow-headers":"authorization, apikey, content-type",
    "access-control-max-age":"86400",
    "vary":"Origin"
  };
}
function corsPreflight(req){
  const origin=req.headers.get("origin")||"";
  if(!CANONICAL_APP_ORIGIN||origin!==CANONICAL_APP_ORIGIN)return Response.json({error:{code:"CORS_ORIGIN_DENIED"}},{status:403});
  return new Response(null,{status:204,headers:corsHeaders(req)});
}
function out(data,status=200,req=null){
  return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff",...corsHeaders(req)}});
}
async function jsonBody(req,max=65536){const contentLength=Number(req.headers.get("content-length")||0);if(Number.isFinite(contentLength)&&contentLength>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};const raw=await req.text();if(new TextEncoder().encode(raw).byteLength>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON"}}}
Deno.serve(async req=>{
  try{
    if(req.method==="OPTIONS")return corsPreflight(req);
    if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405,req);
    const u=await user(req);
    const body=await jsonBody(req);
    const orgId=String(body.orgId||"").trim();
    if(!orgId)return out({error:{code:"ORGANIZATION_REQUIRED"}},400,req);

    const key=await rpc("trustrelay_get_portal_key_v07",{p_auth_user_id:u.id,p_org_id:orgId});
    if(!key?.ok)return out({error:{code:key?.code||"ORGANIZATION_ACCESS_DENIED"}},Number(key?.status)||403,req);

    const partnerBody={...body};
    delete partnerBody.orgId;

    const partner=await fetch(URL+"/functions/v1/trustrelay-partner-v07/v1/decisions/evaluate",{
      method:"POST",
      headers:{
        apikey:pub(),
        "x-trustrelay-key":key.apiKey,
        "content-type":"application/json",
        accept:"application/json"
      },
      body:JSON.stringify(partnerBody)
    });
    const result=await parse(partner);
    if(!result.ok)return out(result.data||{error:{code:"PARTNER_API_ERROR"}},result.status,req);

    await rpc("trustrelay_mark_portal_decision_v07",{
      p_auth_user_id:u.id,p_org_id:orgId,p_request_id:String(partnerBody.requestId||"")
    });

    if(result.data?.decision)result.data.decision.source="portal";
    result.data.portal={organizationId:orgId,role:key.role};
    return out(result.data,200,req);
  }catch(e){
    const status=Number(e?.status)||500;
    return out({error:{code:e?.code||"INTERNAL_ERROR"}},status,req);
  }
});