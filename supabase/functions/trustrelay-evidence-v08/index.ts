import { createClient } from "npm:@supabase/supabase-js@2.117.2";

const URL=Deno.env.get("SUPABASE_URL")||"";
const APP_ORIGIN=(Deno.env.get("TRUSTRELAY_APP_ORIGIN")||"").replace(/\/$/,"");
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function sec(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||""}
function pub(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||Deno.env.get("SUPABASE_ANON_KEY")||""}
function sh(){const k=sec();const h={apikey:k,"content-type":"application/json",accept:"application/json"};if(k&&!k.startsWith("sb_secret_"))h.authorization="Bearer "+k;return h}
async function parse(r){const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}return{ok:r.ok,status:r.status,data:d}}
async function rpc(name,payload){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:sh(),body:JSON.stringify(payload||{})});const x=await parse(r);if(!x.ok)throw{status:503,code:"DATABASE_ERROR"};return x.data}
async function user(req){const auth=req.headers.get("authorization")||"";if(!/^Bearer\s+\S+/i.test(auth))throw{status:401,code:"AUTH_REQUIRED"};const r=await fetch(URL+"/auth/v1/user",{headers:{apikey:pub(),authorization:auth,accept:"application/json"}});if(!r.ok)throw{status:401,code:"INVALID_SESSION"};const u=await r.json();if(!u?.id)throw{status:401,code:"INVALID_SESSION"};return u}
function out(d,s=200,req=null){return Response.json(d,{status:s,headers:{"cache-control":"no-store","x-content-type-options":"nosniff",...corsHeaders(req)}})}
async function sha256Hex(buffer){const d=new Uint8Array(await crypto.subtle.digest("SHA-256",buffer));return[...d].map(b=>b.toString(16).padStart(2,"0")).join("")}
const admin=createClient(URL,sec(),{auth:{persistSession:false,autoRefreshToken:false}});

function corsHeaders(req){
  const origin=req?.headers?.get?.("origin")||"";
  if(!origin||!APP_ORIGIN||origin!==APP_ORIGIN)return{};
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
  if(!APP_ORIGIN||origin!==APP_ORIGIN)return Response.json({error:{code:"CORS_ORIGIN_DENIED"}},{status:403});
  return new Response(null,{status:204,headers:corsHeaders(req)});
}
Deno.serve(async req=>{
 try{
  if(req.method==="OPTIONS")return corsPreflight(req);
  if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405,req);
  const u=await user(req),v=await req.json(),action=String(v.action||"");
  if(action==="prepare"){
    const prepared=await rpc("trustrelay_prepare_document_v08",{
      p_uid:u.id,
      p_proofing_session_id:v.proofingSessionId||null,
      p_purpose:String(v.purpose||"supporting"),
      p_classification:String(v.classification||"other"),
      p_original_filename:String(v.filename||"").slice(0,255),
      p_mime_type:String(v.mimeType||""),
      p_size_bytes:Number(v.sizeBytes||0)
    });
    if(!prepared?.ok)return out({error:{code:prepared?.code||"DOCUMENT_PREPARE_FAILED"}},Number(prepared?.status)||400,req);
    const d=prepared.document;
    const {data,error}=await admin.storage.from(d.storage_bucket).createSignedUploadUrl(d.storage_key,{upsert:false});
    if(error||!data?.token)throw{status:503,code:"SIGNED_UPLOAD_UNAVAILABLE"};
    return out({document:{id:d.id,classification:d.classification,purpose:d.purpose,mimeType:d.mime_type,sizeBytes:d.size_bytes},upload:{bucket:d.storage_bucket,path:d.storage_key,token:data.token}},201,req);
  }
  if(action==="finalize"){
    const access=await rpc("trustrelay_document_access_v08",{p_uid:u.id,p_document_id:String(v.documentId||""),p_mode:"finalize"});
    if(!access?.ok)return out({error:{code:access?.code||"DOCUMENT_ACCESS_DENIED"}},Number(access?.status)||403,req);
    const d=access.document;
    const {data,error}=await admin.storage.from(d.storage_bucket).download(d.storage_key);
    if(error||!data)throw{status:404,code:"UPLOADED_OBJECT_NOT_FOUND"};
    const buf=await data.arrayBuffer(),size=buf.byteLength;
    const type=(data.type||d.mime_type||"").split(";")[0].trim().toLowerCase();
    const allowed=["application/pdf","image/jpeg","image/png","image/webp"];
    const detected=allowed.includes(type)?type:String(d.mime_type||"");
    const hash=await sha256Hex(buf);
    const fin=await rpc("trustrelay_finalize_document_v08",{p_uid:u.id,p_document_id:d.id,p_content_sha256:hash,p_actual_size:size,p_detected_mime:detected});
    if(!fin?.ok)return out({error:{code:fin?.code||"DOCUMENT_FINALIZE_FAILED"}},Number(fin?.status)||400,req);
    return out({document:{id:fin.document.id,classification:fin.document.classification,reviewStatus:fin.document.review_status,scanStatus:fin.document.scan_status,contentSha256:fin.document.content_sha256,sizeBytes:fin.document.size_bytes,finalizedAt:fin.document.finalized_at}},200,req);
  }
  if(action==="download"){
    const access=await rpc("trustrelay_document_access_v08",{p_uid:u.id,p_document_id:String(v.documentId||""),p_mode:"download"});
    if(!access?.ok)return out({error:{code:access?.code||"DOCUMENT_ACCESS_DENIED"}},Number(access?.status)||403);
    const d=access.document;
    const {data,error}=await admin.storage.from(d.storage_bucket).createSignedUrl(d.storage_key,300,{download:d.original_filename||d.display_name||"trustrelay-document"});
    if(error||!data?.signedUrl)throw{status:503,code:"SIGNED_DOWNLOAD_UNAVAILABLE"};
    return out({url:data.signedUrl,expiresIn:300},200,req);
  }
  return out({error:{code:"ACTION_INVALID"}},400,req);
 }catch(e){return out({error:{code:e?.code||"INTERNAL_ERROR"}},Number(e?.status)||500,req)}
});