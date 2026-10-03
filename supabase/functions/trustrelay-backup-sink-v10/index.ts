import { createClient } from "npm:@supabase/supabase-js@2.117.2";
const SB_URL=Deno.env.get("SUPABASE_URL")||"";
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function sec(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
const SERVICE_KEY=sec();
const admin=createClient(SB_URL,SERVICE_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
function sh(){const h={apikey:SERVICE_KEY,"content-type":"application/json",accept:"application/json"};if(SERVICE_KEY&&!SERVICE_KEY.startsWith("sb_secret_"))h.authorization="Bearer "+SERVICE_KEY;return h}
async function rpc(name,payload={}){const r=await fetch(SB_URL+"/rest/v1/rpc/"+name,{method:"POST",headers:sh(),body:JSON.stringify(payload)});const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{};if(!r.ok)throw new Error("RPC_"+name+"_"+r.status);return d}
async function sha256Hex(input){const bytes=input instanceof Uint8Array?input:new TextEncoder().encode(String(input));const d=new Uint8Array(await crypto.subtle.digest("SHA-256",bytes));return[...d].map(b=>b.toString(16).padStart(2,"0")).join("")}
function b64ToBytes(s){const bin=atob(s);const out=new Uint8Array(bin.length);for(let i=0;i<bin.length;i++)out[i]=bin.charCodeAt(i);return out}
function bytesToB64(bytes){let s="";for(let i=0;i<bytes.length;i+=0x8000)s+=String.fromCharCode(...bytes.subarray(i,Math.min(i+0x8000,bytes.length)));return btoa(s)}
function b64uToBytes(s){return b64ToBytes(s.replaceAll("-","+").replaceAll("_","/")+"=".repeat((4-s.length%4)%4))}
async function verifySignedRequest(req,bodyText){
  const ts=req.headers.get("x-trustrelay-ts")||"";
  const kid=req.headers.get("x-trustrelay-kid")||"";
  const sig=req.headers.get("x-trustrelay-signature")||"";
  const tsn=Number(ts);
  if(!Number.isFinite(tsn)||Math.abs(Date.now()-tsn)>300000)throw Object.assign(new Error("BACKUP_SIGNATURE_TIMESTAMP_INVALID"),{status:401});
  const {data:keyRow,error}=await admin.from("backup_source_signing_keys").select("kid,public_jwk,status").eq("kid",kid).eq("status","active").maybeSingle();
  if(error||!keyRow)throw Object.assign(new Error("BACKUP_SIGNING_KEY_UNKNOWN"),{status:401});
  const pub=await crypto.subtle.importKey("jwk",JSON.parse(keyRow.public_jwk),{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
  const bodyHash=await sha256Hex(new TextEncoder().encode(bodyText));
  const msg=new TextEncoder().encode(ts+"\n"+bodyHash);
  const ok=await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},pub,b64uToBytes(sig),msg);
  if(!ok)throw Object.assign(new Error("BACKUP_SIGNATURE_INVALID"),{status:401});
}
async function ensureBucket(){
  const bucket="trustrelay-disaster-recovery";
  const {data}=await admin.storage.getBucket(bucket);
  if(!data){
    const {error}=await admin.storage.createBucket(bucket,{public:false,fileSizeLimit:8388608});
    if(error&&!String(error.message||"").toLowerCase().includes("already"))throw error;
  }
  return bucket;
}
Deno.serve(async req=>{
  try{
    if(SB_URL.includes("msfrbsnihylfynrtdgxe"))return Response.json({error:{code:"BACKUP_SINK_WRONG_ENVIRONMENT"}},{status:503});
    if(req.method==="GET")return Response.json({error:{code:"METHOD_NOT_ALLOWED"}},{status:405,headers:{"allow":"POST","cache-control":"no-store","x-content-type-options":"nosniff"}});
    if(req.method!=="POST")return Response.json({error:{code:"METHOD_NOT_ALLOWED"}},{status:405,headers:{Allow:"POST","cache-control":"no-store","x-content-type-options":"nosniff"}});
    const contentLength=Number(req.headers.get("content-length")||0);
    if(Number.isFinite(contentLength)&&contentLength>6_000_000)return Response.json({error:{code:"PAYLOAD_TOO_LARGE"}},{status:413,headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}});
    const bodyText=await req.text();
    if(bodyText.length>6_000_000)return Response.json({error:{code:"PAYLOAD_TOO_LARGE"}},{status:413,headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}});
    await verifySignedRequest(req,bodyText);
    let v;try{v=bodyText?JSON.parse(bodyText):{}}catch{return Response.json({error:{code:"INVALID_JSON"}},{status:400,headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}})}
    const action=String(v.action||"");
    const bucket=await ensureBucket();

    if(action==="begin"){
      const now=new Date().toISOString();
      const {error}=await admin.from("disaster_recovery_runs").upsert({
        run_id:String(v.runId),source_environment:"production",source_project_ref:"msfrbsnihylfynrtdgxe",
        recovery_key_kid:String(v.recoveryKeyKid),wrapped_data_key_b64:String(v.wrappedDataKeyB64),
        manifest_sha256:null,status:"receiving",created_at:now,completed_at:null
      },{onConflict:"run_id"});
      if(error)throw error;
      return Response.json({ok:true,runId:v.runId});
    }

    if(action==="put"){
      const runId=String(v.runId||""),logicalKey=String(v.logicalKey||"");
      const chunkIndex=Number(v.chunkIndex),totalChunks=Number(v.totalChunks);
      if(!runId||!logicalKey||!Number.isInteger(chunkIndex)||chunkIndex<0||!Number.isInteger(totalChunks)||totalChunks<1)throw Object.assign(new Error("BACKUP_CHUNK_INVALID"),{status:400});
      const cipher=b64ToBytes(String(v.ciphertextB64||""));
      const cipherSha=await sha256Hex(cipher);
      if(cipherSha!==String(v.cipherSha256||""))throw Object.assign(new Error("BACKUP_CIPHER_HASH_MISMATCH"),{status:422});
      const objectId=await sha256Hex(new TextEncoder().encode(logicalKey));
      const path="production/"+runId+"/objects/"+objectId+"/"+String(chunkIndex).padStart(6,"0")+".bin";
      const {error:upErr}=await admin.storage.from(bucket).upload(path,cipher,{upsert:true,contentType:"application/octet-stream"});
      if(upErr)throw upErr;
      const id="dro_"+await sha256Hex(new TextEncoder().encode(runId+"|"+logicalKey+"|"+chunkIndex));
      const {error:dbErr}=await admin.from("disaster_recovery_objects").upsert({
        id,source_environment:"production",run_id:runId,logical_key:logicalKey,chunk_index:chunkIndex,total_chunks:totalChunks,
        storage_bucket:bucket,storage_path:path,iv_b64:String(v.ivB64||""),plain_sha256:String(v.plainSha256||""),
        cipher_sha256:cipherSha,plain_bytes:Number(v.plainBytes||0),cipher_bytes:cipher.length,
        metadata_json:JSON.stringify(v.metadata||{}),created_at:new Date().toISOString()
      },{onConflict:"run_id,logical_key,chunk_index"});
      if(dbErr)throw dbErr;
      return Response.json({ok:true,path,cipherSha256:cipherSha});
    }

    if(action==="complete"){
      const {error}=await admin.from("disaster_recovery_runs").update({
        manifest_sha256:String(v.manifestSha256||""),status:"completed",completed_at:new Date().toISOString()
      }).eq("run_id",String(v.runId||""));
      if(error)throw error;
      return Response.json({ok:true,runId:v.runId});
    }

    if(action==="list"){
      const {data,error}=await admin.from("disaster_recovery_objects").select("*").eq("run_id",String(v.runId||"")).order("logical_key",{ascending:true}).order("chunk_index",{ascending:true});
      if(error)throw error;
      return Response.json({ok:true,objects:data||[]});
    }

    if(action==="get"){
      const {data:row,error}=await admin.from("disaster_recovery_objects").select("*").eq("run_id",String(v.runId||"")).eq("logical_key",String(v.logicalKey||"")).eq("chunk_index",Number(v.chunkIndex)).maybeSingle();
      if(error||!row)throw Object.assign(new Error("BACKUP_OBJECT_NOT_FOUND"),{status:404});
      const {data,error:downErr}=await admin.storage.from(row.storage_bucket).download(row.storage_path);
      if(downErr||!data)throw Object.assign(new Error("BACKUP_OBJECT_DOWNLOAD_FAILED"),{status:503});
      const bytes=new Uint8Array(await data.arrayBuffer());
      return Response.json({ok:true,row,ciphertextB64:bytesToB64(bytes)});
    }

    if(action==="unwrap"){
      const {data:run,error}=await admin.from("disaster_recovery_runs").select("*").eq("run_id",String(v.runId||"")).eq("status","completed").maybeSingle();
      if(error||!run)throw Object.assign(new Error("BACKUP_RUN_NOT_FOUND"),{status:404});
      const keyInfo=await rpc("trustrelay_get_backup_recovery_private_key_v10",{});
      if(!keyInfo?.ok||keyInfo.kid!==run.recovery_key_kid)throw Object.assign(new Error("BACKUP_RECOVERY_KEY_UNAVAILABLE"),{status:503});
      const priv=await crypto.subtle.importKey("jwk",JSON.parse(keyInfo.privateJwk),{name:"RSA-OAEP",hash:"SHA-256"},false,["decrypt"]);
      const raw=new Uint8Array(await crypto.subtle.decrypt({name:"RSA-OAEP"},priv,b64ToBytes(run.wrapped_data_key_b64)));
      return Response.json({ok:true,runId:run.run_id,recoveryKeyKid:run.recovery_key_kid,dataKeyB64:bytesToB64(raw),manifestSha256:run.manifest_sha256});
    }

    return Response.json({error:{code:"ACTION_INVALID"}},{status:400,headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}});
  }catch(e){
    return Response.json({error:{code:String(e?.message||"BACKUP_SINK_ERROR")}},{status:Number(e?.status)||500,headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}});
  }
});