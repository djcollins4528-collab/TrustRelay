import { createClient } from "npm:@supabase/supabase-js@2.117.2";

const URL=Deno.env.get("SUPABASE_URL")||"";
const CANONICAL_APP_ORIGIN=URL.includes("msfrbsnihylfynrtdgxe")?"https://trustrelay-production.onrender.com":URL.includes("kdvroylluosshcjmfbfq")?"https://trustrelay-staging.onrender.com":"";
const APP_ORIGIN=(Deno.env.get("TRUSTRELAY_APP_ORIGIN")||CANONICAL_APP_ORIGIN).replace(/\/$/,"");
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

const SCANNER_VERSION="trustrelay-static-evidence-v1";
function findBytes(haystack,needle){
  outer:for(let i=0;i<=haystack.length-needle.length;i++){
    for(let j=0;j<needle.length;j++)if(haystack[i+j]!==needle[j])continue outer;
    return i;
  }
  return -1;
}
function asciiBytes(s){return new TextEncoder().encode(s)}
function trimEndIndex(bytes){
  let i=bytes.length-1;
  while(i>=0&&(bytes[i]===0x20||bytes[i]===0x09||bytes[i]===0x0a||bytes[i]===0x0d||bytes[i]===0x0c))i--;
  return i;
}
function starts(bytes,sig,offset=0){
  if(bytes.length<offset+sig.length)return false;
  for(let i=0;i<sig.length;i++)if(bytes[offset+i]!==sig[i])return false;
  return true;
}
function detectMime(bytes){
  if(starts(bytes,[0x25,0x50,0x44,0x46,0x2d]))return "application/pdf";
  if(starts(bytes,[0xff,0xd8,0xff]))return "image/jpeg";
  if(starts(bytes,[0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]))return "image/png";
  if(starts(bytes,[0x52,0x49,0x46,0x46])&&starts(bytes,[0x57,0x45,0x42,0x50],8))return "image/webp";
  return "application/octet-stream";
}
function scanEvidence(buffer,declaredMime){
  const bytes=new Uint8Array(buffer);
  const findings=[];
  const detectedMime=detectMime(bytes);
  if(detectedMime==="application/octet-stream")findings.push("UNRECOGNIZED_MAGIC");
  if(detectedMime!==declaredMime)findings.push("MIME_MAGIC_MISMATCH");

  const eicar=asciiBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
  if(findBytes(bytes,eicar)>=0)findings.push("EICAR_TEST_SIGNATURE");

  const masqueradeSignatures=[
    ["PE_MZ",[0x4d,0x5a]],["ELF",[0x7f,0x45,0x4c,0x46]],
    ["ZIP",[0x50,0x4b,0x03,0x04]],["RAR",[0x52,0x61,0x72,0x21,0x1a,0x07]],
    ["SEVEN_ZIP",[0x37,0x7a,0xbc,0xaf,0x27,0x1c]],["GZIP",[0x1f,0x8b]],
    ["OLE_CFBF",[0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1]]
  ];
  for(const [name,sig] of masqueradeSignatures){
    if(starts(bytes,sig))findings.push("DISALLOWED_CONTAINER_"+name);
  }

  if(detectedMime==="application/pdf"){
    const dangerous=["/JavaScript","/JS","/Launch","/EmbeddedFile","/RichMedia","/OpenAction","/AA","/XFA"];
    for(const token of dangerous)if(findBytes(bytes,asciiBytes(token))>=0)findings.push("PDF_ACTIVE_CONTENT_"+token.slice(1).toUpperCase());
    const end=trimEndIndex(bytes);
    const eof=asciiBytes("%%EOF");
    if(end<eof.length-1||!starts(bytes,[...eof],end-eof.length+1))findings.push("PDF_TRAILER_INVALID");
  } else if(detectedMime==="image/jpeg"){
    const end=trimEndIndex(bytes);
    if(end<1||bytes[end-1]!==0xff||bytes[end]!==0xd9)findings.push("JPEG_TRAILER_INVALID");
  } else if(detectedMime==="image/png"){
    let pos=8,sawIend=false;
    while(pos+12<=bytes.length){
      const len=((bytes[pos]<<24)>>>0)|(bytes[pos+1]<<16)|(bytes[pos+2]<<8)|bytes[pos+3];
      const type=String.fromCharCode(bytes[pos+4],bytes[pos+5],bytes[pos+6],bytes[pos+7]);
      const next=pos+12+len;
      if(next>bytes.length){findings.push("PNG_CHUNK_BOUNDS_INVALID");break}
      if(type==="IEND"){
        sawIend=true;
        if(len!==0||next!==bytes.length)findings.push("PNG_TRAILING_OR_IEND_INVALID");
        break;
      }
      pos=next;
    }
    if(!sawIend)findings.push("PNG_IEND_MISSING");
  } else if(detectedMime==="image/webp"){
    if(bytes.length<12)findings.push("WEBP_HEADER_INVALID");
    else{
      const riffSize=(bytes[4]|(bytes[5]<<8)|(bytes[6]<<16)|(bytes[7]<<24))>>>0;
      if(riffSize+8!==bytes.length)findings.push("WEBP_SIZE_OR_TRAILING_INVALID");
    }
  }

  return {
    scannerVersion:SCANNER_VERSION,
    verdict:findings.length?"rejected":"clean",
    detectedMime,
    findings,
    checks:{
      strictAllowlist:true,
      magicBytes:true,
      eicarSignature:true,
      executableArchiveMasquerade:true,
      pdfActiveContent:true,
      trailingPolyglot:true
    }
  };
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
async function readJsonBounded(req,maxBytes=65536){
  const declared=Number(req.headers.get("content-length")||0);
  if(Number.isFinite(declared)&&declared>maxBytes)throw{status:413,code:"REQUEST_TOO_LARGE"};
  const raw=await req.text();
  if(new TextEncoder().encode(raw).length>maxBytes)throw{status:413,code:"REQUEST_TOO_LARGE"};
  try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"JSON_INVALID"}}
}
Deno.serve(async req=>{
 try{
  if(req.method==="OPTIONS")return corsPreflight(req);
  if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405,req);
  const u=await user(req),v=await readJsonBounded(req),action=String(v.action||"");
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
    const declared=(d.mime_type||"").split(";")[0].trim().toLowerCase();
    const hash=await sha256Hex(buf);
    const scan=scanEvidence(buf,declared);
    if(scan.verdict!=="clean"){
      await rpc("trustrelay_reject_document_scan_v10",{
        p_uid:u.id,p_document_id:d.id,p_content_sha256:hash,p_actual_size:size,
        p_detected_mime:scan.detectedMime,p_scan_result_json:JSON.stringify(scan)
      });
      await admin.storage.from(d.storage_bucket).remove([d.storage_key]);
      return out({error:{code:"DOCUMENT_MALWARE_SCAN_REJECTED",findings:scan.findings}},422,req);
    }
    const fin=await rpc("trustrelay_finalize_document_v10",{
      p_uid:u.id,p_document_id:d.id,p_content_sha256:hash,p_actual_size:size,
      p_detected_mime:scan.detectedMime,p_scan_result_json:JSON.stringify(scan)
    });
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