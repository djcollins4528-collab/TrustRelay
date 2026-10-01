
const URL=Deno.env.get("SUPABASE_URL")||"";
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function secret(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||""}
function headers(){const k=secret();const h={"apikey":k,"content-type":"application/json","accept":"application/json"};if(k&&!k.startsWith("sb_secret_"))h["authorization"]="Bearer "+k;return h}
async function rpc(name,body){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:headers(),body:JSON.stringify(body||{})});const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}if(!r.ok||d?.ok===false)throw{status:Number(d?.status)||r.status||400,code:d?.code||"REQUEST_REJECTED"};return d}
function b64decode(v){const s=v.replaceAll("-","+").replaceAll("_","/")+"===".slice((v.length+3)%4),r=atob(s);return new Uint8Array([...r].map(c=>c.charCodeAt(0)))}
function jsonpart(v){return JSON.parse(new TextDecoder().decode(b64decode(v)))}
function id(p){return p+crypto.randomUUID().replaceAll("-","")}
async function hex(t){return[...new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(t)))].map(b=>b.toString(16).padStart(2,"0")).join("")}

Deno.serve(async ()=>{
 try{
   const d=await rpc("trustrelay_list_public_signing_keys_v06",{});
   const keys=(d.keys||[]).map(x=>({...x.publicJwk,kid:x.kid,alg:x.alg,use:"sig"}));
   return Response.json({keys},{headers:{"cache-control":"public, max-age=300","x-content-type-options":"nosniff"}});
 }catch{return Response.json({error:{code:"KEY_REGISTRY_UNAVAILABLE"}},{status:503})}
});