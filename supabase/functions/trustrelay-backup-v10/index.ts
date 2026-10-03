import { createClient } from "npm:@supabase/supabase-js@2.117.2";
import { S3Client, PutObjectCommand, GetObjectCommand } from "npm:@aws-sdk/client-s3@3.917.0";

const URL=Deno.env.get("SUPABASE_URL")||"";
const ENVIRONMENT=URL.includes("msfrbsnihylfynrtdgxe")?"production":URL.includes("kdvroylluosshcjmfbfq")?"staging":"unknown";

function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function secretKey(){
  const values=envJson("SUPABASE_SECRET_KEYS");
  return values.default||Object.values(values).find(v=>typeof v==="string"&&v)||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||"";
}
const SERVICE_KEY=secretKey();
const admin=createClient(URL,SERVICE_KEY,{auth:{persistSession:false,autoRefreshToken:false}});

function serviceHeaders(){
  const h={apikey:SERVICE_KEY,"content-type":"application/json",accept:"application/json"};
  if(SERVICE_KEY&&!SERVICE_KEY.startsWith("sb_secret_"))h.authorization="Bearer "+SERVICE_KEY;
  return h;
}
async function rpc(name,payload={}){
  const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:serviceHeaders(),body:JSON.stringify(payload)});
  const t=await r.text();
  let d=null;try{d=t?JSON.parse(t):null}catch{}
  if(!r.ok)throw new Error("RPC_"+name+"_HTTP_"+r.status);
  return d;
}
function out(data,status=200){
  return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}});
}
async function sha256Hex(input){
  const bytes=input instanceof Uint8Array?input:new TextEncoder().encode(String(input));
  const digest=new Uint8Array(await crypto.subtle.digest("SHA-256",bytes));
  return [...digest].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function bytesFromString(s){return new TextEncoder().encode(s)}
async function bodyBytes(body){
  if(!body)return new Uint8Array();
  if(typeof body.transformToByteArray==="function")return new Uint8Array(await body.transformToByteArray());
  if(typeof body.arrayBuffer==="function")return new Uint8Array(await body.arrayBuffer());
  const chunks=[];let total=0;
  for await(const chunk of body){
    const u=chunk instanceof Uint8Array?chunk:new Uint8Array(chunk);
    chunks.push(u);total+=u.length;
  }
  const merged=new Uint8Array(total);let off=0;
  for(const u of chunks){merged.set(u,off);off+=u.length}
  return merged;
}
async function validateTrigger(req){
  const token=req.headers.get("x-trustrelay-backup-token")||"";
  const result=await rpc("trustrelay_validate_backup_trigger_v10",{p_token:token});
  if(!result?.ok)throw Object.assign(new Error(result?.code||"BACKUP_TRIGGER_INVALID"),{status:Number(result?.status)||401,code:result?.code||"BACKUP_TRIGGER_INVALID"});
}
async function loadConfig(){
  const c=await rpc("trustrelay_backup_config_v10",{});
  if(!c?.ok)throw Object.assign(new Error("R2_CONFIG_NOT_READY"),{status:503,code:"R2_CONFIG_NOT_READY"});
  if(c.jurisdiction!=="us")throw Object.assign(new Error("R2_US_JURISDICTION_REQUIRED"),{status:503,code:"R2_US_JURISDICTION_REQUIRED"});
  return c;
}
function r2Client(c){
  return new S3Client({
    region:"auto",
    endpoint:`https://${c.accountId}.${c.jurisdiction}.r2.cloudflarestorage.com`,
    credentials:{accessKeyId:c.accessKeyId,secretAccessKey:c.secretAccessKey},
    forcePathStyle:true
  });
}
async function putObject(s3,c,key,bytes,contentType,metadata={}){
  const sha=await sha256Hex(bytes);
  await s3.send(new PutObjectCommand({
    Bucket:c.bucket,Key:key,Body:bytes,ContentType:contentType,
    Metadata:{sha256:sha,...metadata}
  }));
  return {key,sha256:sha,bytes:bytes.length};
}
async function getObject(s3,c,key){
  const r=await s3.send(new GetObjectCommand({Bucket:c.bucket,Key:key}));
  return await bodyBytes(r.Body);
}
async function listStorageObjects(bucketId,prefix="",found=[]){
  const limit=1000;
  for(let offset=0;;offset+=limit){
    const {data,error}=await admin.storage.from(bucketId).list(prefix,{limit,offset,sortBy:{column:"name",order:"asc"}});
    if(error)throw new Error("STORAGE_LIST_FAILED_"+bucketId);
    const items=data||[];
    for(const item of items){
      const path=prefix?prefix+"/"+item.name:item.name;
      if(item.id){
        found.push(path);
      }else{
        await listStorageObjects(bucketId,path,found);
      }
    }
    if(items.length<limit)break;
  }
  return found;
}
async function performBackup(){
  const c=await loadConfig();
  const s3=r2Client(c);
  const now=new Date();
  const date=now.toISOString().slice(0,10).replaceAll("-","/");
  const runId="backup_"+crypto.randomUUID().replaceAll("-","");
  const prefix=`${ENVIRONMENT}/${date}/${runId}`;
  await rpc("trustrelay_backup_run_start_v10",{p_id:runId,p_environment:ENVIRONMENT,p_bucket:c.bucket,p_object_prefix:prefix});

  const manifest={
    formatVersion:"trustrelay-backup-v1",
    runId,environment:ENVIRONMENT,provider:"cloudflare_r2",
    jurisdiction:"us",createdAt:now.toISOString(),
    schemaSource:"canonical GitHub migrations",
    excludedSecurityState:["auth.sessions","refresh tokens","Edge Function secrets","Vault plaintext","live API secret material"],
    tables:[],storage:[],objects:[]
  };

  try{
    const inv=await rpc("trustrelay_backup_inventory_v10",{});
    if(!inv?.ok)throw new Error("BACKUP_INVENTORY_FAILED");

    let totalRows=0;
    for(const t of inv.tables||[]){
      let offset=0,page=0,tableRows=0;
      for(;;){
        const p=await rpc("trustrelay_backup_page_v10",{p_schema:t.schema,p_table:t.table,p_offset:offset,p_limit:500});
        if(!p?.ok)throw new Error("BACKUP_PAGE_FAILED_"+t.schema+"_"+t.table);
        const rows=p.rows||[];
        if(rows.length===0)break;
        const payload=bytesFromString(JSON.stringify({schema:t.schema,table:t.table,offset,rows}));
        const key=`${prefix}/tables/${t.schema}/${t.table}/${String(page).padStart(6,"0")}.json`;
        const saved=await putObject(s3,c,key,payload,"application/json",{kind:"table_page",schema:t.schema,table:t.table});
        manifest.objects.push({...saved,kind:"table_page",schema:t.schema,table:t.table,rowCount:rows.length});
        tableRows+=rows.length;totalRows+=rows.length;
        offset+=rows.length;page++;
        if(rows.length<500)break;
      }
      manifest.tables.push({schema:t.schema,table:t.table,rowCount:tableRows,pages:page});
    }

    const {data:buckets,error:bucketError}=await admin.storage.listBuckets();
    if(bucketError)throw new Error("STORAGE_BUCKET_LIST_FAILED");
    let storageObjects=0,storageBytes=0;
    for(const bucket of buckets||[]){
      const paths=await listStorageObjects(bucket.id);
      let bucketCount=0,bucketBytes=0;
      for(const path of paths){
        const {data,error}=await admin.storage.from(bucket.id).download(path);
        if(error||!data)throw new Error("STORAGE_DOWNLOAD_FAILED_"+bucket.id);
        const bytes=new Uint8Array(await data.arrayBuffer());
        const key=`${prefix}/storage/${encodeURIComponent(bucket.id)}/${path}`;
        const saved=await putObject(s3,c,key,bytes,data.type||"application/octet-stream",{kind:"storage_object",bucket:bucket.id});
        manifest.objects.push({...saved,kind:"storage_object",bucket:bucket.id,sourcePath:path,contentType:data.type||"application/octet-stream"});
        bucketCount++;bucketBytes+=bytes.length;storageObjects++;storageBytes+=bytes.length;
      }
      manifest.storage.push({bucket:bucket.id,objectCount:bucketCount,bytes:bucketBytes,public:Boolean(bucket.public)});
    }

    manifest.summary={tableCount:manifest.tables.length,rowCount:totalRows,storageObjectCount:storageObjects,storageBytes,objectCount:manifest.objects.length};
    const manifestBytes=bytesFromString(JSON.stringify(manifest));
    const manifestKey=`${prefix}/manifest.json`;
    const savedManifest=await putObject(s3,c,manifestKey,manifestBytes,"application/json",{kind:"manifest",run_id:runId});
    await rpc("trustrelay_backup_run_finish_v10",{
      p_id:runId,p_manifest_key:manifestKey,p_manifest_sha256:savedManifest.sha256,
      p_table_count:manifest.tables.length,p_row_count:totalRows,
      p_storage_object_count:storageObjects,p_storage_bytes:storageBytes
    });
    return {ok:true,runId,manifestKey,manifestSha256:savedManifest.sha256,summary:manifest.summary};
  }catch(error){
    await rpc("trustrelay_backup_run_fail_v10",{p_id:runId,p_error_code:"BACKUP_FAILED",p_error_message:String(error?.message||error)}).catch(()=>{});
    throw error;
  }
}
async function performIntegrityRehearsal(runIdInput){
  const c=await loadConfig(),s3=r2Client(c);
  let run=null;
  if(runIdInput){
    const {data,error}=await admin.from("backup_runs").select("*").eq("id",runIdInput).eq("status","completed").maybeSingle();
    if(error)throw error;run=data;
  }else{
    const {data,error}=await admin.from("backup_runs").select("*").eq("status","completed").order("started_at",{ascending:false}).limit(1).maybeSingle();
    if(error)throw error;run=data;
  }
  if(!run)throw Object.assign(new Error("COMPLETED_BACKUP_NOT_FOUND"),{status:404,code:"COMPLETED_BACKUP_NOT_FOUND"});

  const testId="restoretest_"+crypto.randomUUID().replaceAll("-","");
  await rpc("trustrelay_backup_restore_test_start_v10",{p_id:testId,p_backup_run_id:run.id});

  const manifestBytes=await getObject(s3,c,run.manifest_key);
  const manifestSha=await sha256Hex(manifestBytes);
  const manifest=JSON.parse(new TextDecoder().decode(manifestBytes));
  let mismatches=manifestSha===run.manifest_sha256?0:1;
  let checkedObjects=1,checkedBytes=manifestBytes.length;
  const evidenceParts=[run.id,manifestSha];

  for(const entry of manifest.objects||[]){
    const bytes=await getObject(s3,c,entry.key);
    const sha=await sha256Hex(bytes);
    checkedObjects++;checkedBytes+=bytes.length;
    if(sha!==entry.sha256||bytes.length!==entry.bytes)mismatches++;
    if(entry.kind==="table_page"){
      const parsed=JSON.parse(new TextDecoder().decode(bytes));
      if(!Array.isArray(parsed.rows))mismatches++;
    }
    evidenceParts.push(entry.key,sha,String(bytes.length));
  }

  const evidenceHash=await sha256Hex(bytesFromString(evidenceParts.join("|")));
  await rpc("trustrelay_backup_restore_test_finish_v10",{
    p_id:testId,p_checked_objects:checkedObjects,p_checked_bytes:checkedBytes,
    p_mismatch_count:mismatches,p_evidence_hash:evidenceHash
  });
  return {ok:mismatches===0,testId,backupRunId:run.id,checkedObjects,checkedBytes,mismatches,evidenceHash};
}

Deno.serve(async req=>{
  try{
    if(req.method==="GET"){
      const config=await rpc("trustrelay_backup_config_v10",{}).catch(()=>({ok:false}));
      return out({ok:true,service:"trustrelay-backup-v10",environment:ENVIRONMENT,configReady:Boolean(config?.ok)});
    }
    if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405);
    await validateTrigger(req);
    const body=await req.json().catch(()=>({}));
    const action=String(body.action||"run");
    if(action==="run")return out(await performBackup(),200);
    if(action==="verify")return out(await performIntegrityRehearsal(body.runId||null),200);
    return out({error:{code:"ACTION_INVALID"}},400);
  }catch(error){
    return out({error:{code:error?.code||"BACKUP_INTERNAL_ERROR",message:String(error?.message||error)}},Number(error?.status)||500);
  }
});
