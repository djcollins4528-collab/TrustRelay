
const URL=Deno.env.get("SUPABASE_URL")||"";
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function secret(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function headers(){const k=secret();const h={"apikey":k,"content-type":"application/json","accept":"application/json"};if(k&&!k.startsWith("sb_secret_"))h["authorization"]="Bearer "+k;return h}
function sub(req){const a=req.headers.get("authorization")||"",t=a.replace(/^Bearer\s+/i,""),p=t.split(".")[1];if(!p)throw new Error("auth");const s=p.replaceAll("-","+").replaceAll("_","/")+"===".slice((p.length+3)%4);return JSON.parse(atob(s)).sub}
async function rpc(name,body){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:headers(),body:JSON.stringify(body)});const d=await r.json();if(!r.ok||d?.ok===false)throw{status:Number(d?.status)||r.status||400,code:d?.code||"REQUEST_REJECTED"};return d}
async function jsonBody(req,max=16384){const raw=await req.text();if(raw.length>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON"}}}
async function sha(t){return[...new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(t)))].map(b=>b.toString(16).padStart(2,"0")).join("")}

Deno.serve(async req=>{
  try{
    if(req.method!=="POST")return Response.json({error:{code:"METHOD_NOT_ALLOWED"}},{status:405});
    const uid=sub(req);
    const v=await jsonBody(req);
    const token=typeof v.token==="string"?v.token.trim():"";
    if(!token)throw{status:400,code:"INVITATION_TOKEN_REQUIRED"};
    const d=await rpc("trustrelay_preview_invitation_v061",{p_auth_user_id:uid,p_token_hash:await sha(token)});
    return Response.json(d,{headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}});
  }catch(e){
    return Response.json({error:{code:e?.code||"AUTH_REQUIRED"}},{status:Number(e?.status)||401,headers:{"cache-control":"no-store"}});
  }
});