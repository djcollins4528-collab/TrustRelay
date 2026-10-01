
const URL=Deno.env.get("SUPABASE_URL")||"";
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
Deno.serve(async req=>{
  try{
    if(req.method!=="POST")return Response.json({error:{code:"METHOD_NOT_ALLOWED"}},{status:405});
    const u=await user(req);
    const body=await req.json();
    const orgId=String(body.orgId||"").trim();
    if(!orgId)return Response.json({error:{code:"ORGANIZATION_REQUIRED"}},{status:400});

    const key=await rpc("trustrelay_get_portal_key_v07",{p_auth_user_id:u.id,p_org_id:orgId});
    if(!key?.ok)return Response.json({error:{code:key?.code||"ORGANIZATION_ACCESS_DENIED"}},{status:Number(key?.status)||403});

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
    if(!result.ok)return Response.json(result.data||{error:{code:"PARTNER_API_ERROR"}},{status:result.status});

    await rpc("trustrelay_mark_portal_decision_v07",{
      p_auth_user_id:u.id,p_org_id:orgId,p_request_id:String(partnerBody.requestId||"")
    });

    if(result.data?.decision)result.data.decision.source="portal";
    result.data.portal={organizationId:orgId,role:key.role};
    return Response.json(result.data,{headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}});
  }catch(e){
    const status=Number(e?.status)||500;
    return Response.json({error:{code:e?.code||"INTERNAL_ERROR"}},{status,headers:{"cache-control":"no-store"}});
  }
});