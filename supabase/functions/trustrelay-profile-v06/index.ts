
const URL=Deno.env.get("SUPABASE_URL")||"";
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function secret(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function headers(){const k=secret();const h={"apikey":k,"content-type":"application/json","accept":"application/json"};if(k&&!k.startsWith("sb_secret_"))h["authorization"]="Bearer "+k;return h}
function pub(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||""}
async function user(req){const auth=req.headers.get("authorization")||"";if(!/^Bearer\s+\S+/i.test(auth))throw{status:401,code:"AUTH_REQUIRED"};const k=pub();if(!k)throw{status:503,code:"AUTH_RUNTIME_CONFIG_MISSING"};const r=await fetch(URL+"/auth/v1/user",{headers:{apikey:k,authorization:auth,accept:"application/json"}});if(!r.ok)throw{status:401,code:"INVALID_SESSION"};const u=await r.json();if(!u?.id)throw{status:401,code:"INVALID_SESSION"};return u}
async function rpc(name,body){
  const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:headers(),body:JSON.stringify(body)});
  const d=await r.json();
  if(!r.ok||d?.ok===false) return Response.json({error:{code:d?.code||"REQUEST_REJECTED"}},{status:Number(d?.status)||r.status||400});
  return Response.json(d,{headers:{"cache-control":"no-store"}});
}
Deno.serve(async req=>{
  try{
    const uid=(await user(req)).id;
    if(req.method==="POST") return await rpc("trustrelay_ensure_account_v06",{p_auth_user_id:uid,p_display_name:null});
    if(req.method==="GET") return await rpc("trustrelay_list_grants_v06",{p_auth_user_id:uid});
    return Response.json({error:{code:"METHOD_NOT_ALLOWED"}},{status:405});
  }catch{return Response.json({error:{code:"AUTH_REQUIRED"}},{status:401})}
});