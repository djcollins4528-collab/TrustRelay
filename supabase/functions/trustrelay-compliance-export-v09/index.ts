
import { createClient } from "npm:@supabase/supabase-js@2.117.2";

const URL=Deno.env.get("SUPABASE_URL")||"";
const CANONICAL_APP_ORIGIN=URL.includes("msfrbsnihylfynrtdgxe")?"https://trustrelay-production.onrender.com":URL.includes("kdvroylluosshcjmfbfq")?"https://trustrelay-staging.onrender.com":"";
const APP_ORIGIN=(Deno.env.get("TRUSTRELAY_APP_ORIGIN")||CANONICAL_APP_ORIGIN).replace(/\/$/,"");
function envJson(n){try{return JSON.parse(Deno.env.get(n)||"{}")}catch{return{}}}
function sec(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||""}
function pub(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||Deno.env.get("SUPABASE_ANON_KEY")||""}
function sh(){const k=sec();const h={apikey:k,"content-type":"application/json",accept:"application/json"};if(k&&!k.startsWith("sb_secret_"))h.authorization="Bearer "+k;return h}
function out(d,s=200,req=null){return Response.json(d,{status:s,headers:{"cache-control":"no-store","x-content-type-options":"nosniff",...corsHeaders(req)}})}
async function parse(r){const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}return{ok:r.ok,status:r.status,data:d}}
async function user(req){
  const auth=req.headers.get("authorization")||"";
  if(!/^Bearer\s+\S+/i.test(auth))throw{status:401,code:"AUTH_REQUIRED"};
  const r=await fetch(URL+"/auth/v1/user",{headers:{apikey:pub(),authorization:auth,accept:"application/json"}});
  if(!r.ok)throw{status:401,code:"INVALID_SESSION"};
  const u=await r.json();if(!u?.id)throw{status:401,code:"INVALID_SESSION"};
  return{user:u,auth};
}
async function userRpc(auth,name,payload){
  const r=await fetch(URL+"/rest/v1/rpc/"+name,{
    method:"POST",
    headers:{apikey:pub(),authorization:auth,"content-type":"application/json",accept:"application/json"},
    body:JSON.stringify(payload||{})
  });
  const x=await parse(r);
  if(!x.ok)throw{status:x.status,code:x.data?.code||"REQUEST_FAILED"};
  if(x.data?.ok===false)throw{status:Number(x.data.status)||400,code:x.data.code||"REQUEST_REJECTED"};
  return x.data;
}
async function rpc(name,payload){
  const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:sh(),body:JSON.stringify(payload||{})});
  const x=await parse(r);if(!x.ok)throw{status:503,code:"DATABASE_ERROR"};
  return x.data;
}
async function hashHex(bytes){
  const d=new Uint8Array(await crypto.subtle.digest("SHA-256",bytes));
  return[...d].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function csvEscape(v){
  const s=typeof v==="string"?v:JSON.stringify(v);
  return '"'+String(s??"").replaceAll('"','""')+'"';
}
function recordId(row){return row?.id||row?.eventId||row?.requestId||row?.accountId||""}
function occurredAt(row){return row?.decidedAt||row?.decided_at||row?.createdAt||row?.created_at||row?.completedAt||row?.updatedAt||""}
function sectionCounts(dataset){
  const out={};const data=dataset?.data||{};
  for(const [key,value] of Object.entries(data)){
    if(Array.isArray(value))out[key]=value.length;
    else if(value&&typeof value==="object"){
      for(const [subKey,subValue] of Object.entries(value)){
        if(Array.isArray(subValue))out[key+"."+subKey]=subValue.length;
      }
    }
  }
  return out;
}
function toCsv(dataset,manifest){
  const rows=[["record_type","record_id","occurred_at","payload_json"]];
  rows.push(["manifest",dataset?.export?.id||"",dataset?.export?.createdAt||"",manifest]);
  const data=dataset?.data||{};
  for(const [key,value] of Object.entries(data)){
    if(Array.isArray(value)){
      for(const row of value)rows.push([key,recordId(row),occurredAt(row),row]);
    }else if(value&&typeof value==="object"){
      let expanded=false;
      for(const [subKey,subValue] of Object.entries(value)){
        if(Array.isArray(subValue)){
          expanded=true;
          for(const row of subValue)rows.push([key+"."+subKey,recordId(row),occurredAt(row),row]);
        }
      }
      if(!expanded)rows.push([key,"","",value]);
    }else{
      rows.push([key,"","",value]);
    }
  }
  return rows.map(r=>r.map(csvEscape).join(",")).join("\r\n")+"\r\n";
}
const admin=createClient(URL,sec(),{auth:{persistSession:false,autoRefreshToken:false}});

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
Deno.serve(async req=>{
  try{
    if(req.method==="OPTIONS")return corsPreflight(req);
    if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405,req);
    const session=await user(req);
    const body=await req.json();
    const action=String(body.action||"");

    if(action==="list"){
      const center=await userRpc(session.auth,"trustrelay_compliance_center_v09",{p_org_id:String(body.orgId||"")});
      return out(center,200,req);
    }

    if(action==="download"){
      const orgId=String(body.orgId||"");
      const exportId=String(body.exportId||"");
      const center=await userRpc(session.auth,"trustrelay_compliance_center_v09",{p_org_id:orgId});
      const item=(center.exports||[]).find(x=>x.id===exportId);
      if(!item)throw{status:404,code:"EXPORT_NOT_FOUND"};
      if(item.status!=="ready")throw{status:409,code:"EXPORT_NOT_READY"};
      if(item.expiresAt&&new Date(item.expiresAt).getTime()<=Date.now())throw{status:410,code:"EXPORT_EXPIRED"};

      const {data:record,error:recordError}=await admin
        .from("compliance_exports")
        .select("storage_bucket,storage_key,format")
        .eq("id",exportId).eq("organization_id",orgId).single();
      if(recordError||!record)throw{status:404,code:"EXPORT_NOT_FOUND"};

      const {data,error}=await admin.storage
        .from(record.storage_bucket)
        .createSignedUrl(record.storage_key,300,{download:"trustrelay-"+exportId+"."+record.format});
      if(error||!data?.signedUrl)throw{status:503,code:"EXPORT_DOWNLOAD_UNAVAILABLE"};
      return out({url:data.signedUrl,expiresIn:300,export:item},200,req);
    }

    if(!["create","generate"].includes(action))throw{status:400,code:"ACTION_INVALID"};

    const requested=await userRpc(session.auth,"trustrelay_request_compliance_export_v09",{
      p_org_id:String(body.orgId||""),
      p_scopes:Array.isArray(body.scopes)?body.scopes:[],
      p_format:String(body.format||"json"),
      p_from_at:body.fromAt||null,
      p_to_at:body.toAt||null
    });
    const exp=requested.export;
    let dataset;
    try{
      dataset=await rpc("trustrelay_export_dataset_v09",{p_export_id:exp.id});
      if(!dataset?.ok)throw new Error(dataset?.code||"EXPORT_DATASET_FAILED");

      const generatedAt=new Date().toISOString();
      const sourceDatasetSha256=await hashHex(new TextEncoder().encode(JSON.stringify(dataset)));
      const manifest={
        schemaVersion:"trustrelay-compliance-0.9",
        generatedAt,
        export:dataset.export,
        organization:dataset.organization,
        scopes:dataset.export?.scopes||[],
        auditChain:dataset.auditChain,
        recordCounts:sectionCounts(dataset),
        rowCount:Number(dataset.rowCount||0),
        sourceDatasetSha256
      };
      const payload=exp.format==="csv"
        ? toCsv(dataset,manifest)
        : JSON.stringify({manifest,data:dataset.data},null,2)+"\n";
      const bytes=new TextEncoder().encode(payload);
      if(bytes.byteLength>20971520)throw{status:413,code:"EXPORT_TOO_LARGE"};
      const contentSha256=await hashHex(bytes);
      const storedManifest={...manifest,contentSha256};
      const contentType=exp.format==="csv"?"text/csv":"application/json";

      const {error:uploadError}=await admin.storage
        .from(exp.storageBucket)
        .upload(exp.storageKey,bytes,{contentType,upsert:false});
      if(uploadError)throw new Error("EXPORT_STORAGE_"+uploadError.message);

      const finalized=await rpc("trustrelay_finalize_compliance_export_v09",{
        p_export_id:exp.id,
        p_content_sha256:contentSha256,
        p_size_bytes:bytes.byteLength,
        p_row_count:Number(dataset.rowCount||0),
        p_manifest_json:JSON.stringify(storedManifest)
      });
      if(!finalized?.ok)throw new Error(finalized?.code||"EXPORT_FINALIZE_FAILED");

      const {data:signed,error:signedError}=await admin.storage
        .from(exp.storageBucket)
        .createSignedUrl(exp.storageKey,300,{download:"trustrelay-"+exp.id+"."+exp.format});
      return out({
        ok:true,
        export:finalized.export,
        manifest:storedManifest,
        url:signedError?null:signed?.signedUrl||null,
        expiresIn:signedError?null:300
      },201,req);
    }catch(e){
      await rpc("trustrelay_fail_compliance_export_v09",{
        p_export_id:exp.id,
        p_error_code:"EXPORT_BUILD_FAILED",
        p_error_detail:String(e?.message||e).slice(0,1000)
      }).catch(()=>{});
      throw e;
    }
  }catch(e){
    return out({error:{code:e?.code||"INTERNAL_ERROR"}},Number(e?.status)||500,req);
  }
});