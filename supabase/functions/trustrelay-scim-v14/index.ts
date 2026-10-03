const SUPABASE_URL=(Deno.env.get("SUPABASE_URL")||"").replace(/\/$/,"");
const STAGING_REF="kdvroylluosshcjmfbfq";
const PRODUCTION_REF="msfrbsnihylfynrtdgxe";
const PUBLIC_ORIGIN=SUPABASE_URL.includes(STAGING_REF)
  ?"https://trustrelay-staging.onrender.com"
  :SUPABASE_URL.includes(PRODUCTION_REF)
    ?"https://trustrelay-production.onrender.com":"";
const SCIM_BASE=PUBLIC_ORIGIN+"/scim/v2";
const USER_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA="urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA="urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_SCHEMA="urn:ietf:params:scim:api:messages:2.0:PatchOp";
const MAX_BODY=262144;
const MAX_PAGE=200;

function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function secretKey(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
const SECRET_KEY=secretKey();

function serviceHeaders(extra={}){
  const h={apikey:SECRET_KEY,accept:"application/json",...extra};
  if(SECRET_KEY&&!SECRET_KEY.startsWith("sb_secret_"))h.authorization="Bearer "+SECRET_KEY;
  return h;
}
function scimHeaders(extra={}){
  return {"content-type":"application/scim+json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff",...extra};
}
function scim(data,status=200,extra={}){
  return new Response(data===null?null:JSON.stringify(data),{status,headers:scimHeaders(extra)});
}
function scimError(status,detail,scimType=null){
  const body={schemas:[ERROR_SCHEMA],status:String(status),detail:String(detail||"Request failed")};
  if(scimType)body.scimType=scimType;
  return scim(body,status);
}
function oauth(data,status=200,extra={}){
  return new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","pragma":"no-cache",...extra}});
}
function pathFor(req){
  const p=new URL(req.url).pathname;
  const marker="/trustrelay-scim-v14";
  const i=p.indexOf(marker);
  return i>=0?(p.slice(i+marker.length)||"/"):p;
}
async function jsonBody(req){
  const declared=Number(req.headers.get("content-length")||0);
  if(Number.isFinite(declared)&&declared>MAX_BODY)throw {status:413,code:"PAYLOAD_TOO_LARGE"};
  const raw=await req.text();
  if(new TextEncoder().encode(raw).byteLength>MAX_BODY)throw {status:413,code:"PAYLOAD_TOO_LARGE"};
  try{return raw?JSON.parse(raw):{}}catch{throw {status:400,code:"INVALID_JSON"}}
}
async function sha256(value){
  const b=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(String(value||"")));
  return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
function randomToken(prefix,bytes=32){
  const a=new Uint8Array(bytes);crypto.getRandomValues(a);
  let s="";for(const b of a)s+=String.fromCharCode(b);
  return prefix+btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
async function parseResponse(r){
  const text=await r.text();let data=null;
  try{data=text?JSON.parse(text):null}catch{}
  return {ok:r.ok,status:r.status,data,text,headers:r.headers};
}
async function rpc(name,body){
  const r=await fetch(SUPABASE_URL+"/rest/v1/rpc/"+name,{
    method:"POST",
    headers:serviceHeaders({"content-type":"application/json"}),
    body:JSON.stringify(body||{})
  });
  const x=await parseResponse(r);
  if(!x.ok)throw {status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR"};
  if(x.data?.ok===false)throw {status:Number(x.data.status)||400,code:x.data.code||"REQUEST_REJECTED",details:x.data};
  return x.data;
}
async function rest(table,{method="GET",filters={},body=null,select="*",range=null,prefer=null}={}){
  const u=new URL(SUPABASE_URL+"/rest/v1/"+table);
  u.searchParams.set("select",select);
  for(const [k,v] of Object.entries(filters||{}))if(v!==undefined&&v!==null)u.searchParams.set(k,String(v));
  const h=serviceHeaders();
  if(body!==null)h["content-type"]="application/json";
  if(range){h["Range-Unit"]="items";h["Range"]=range}
  if(prefer)h["Prefer"]=prefer;
  const r=await fetch(u,{method,headers:h,body:body===null?undefined:JSON.stringify(body)});
  const x=await parseResponse(r);
  if(!x.ok)throw {status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR",details:x.data};
  return x;
}
function listResponse(rows,total,startIndex){
  return {schemas:[LIST_SCHEMA],totalResults:total,startIndex,itemsPerPage:rows.length,Resources:rows};
}
function parseTotal(headers,fallback){
  const cr=headers.get("content-range")||"";
  const m=cr.match(/\/(\d+|\*)$/);
  return m&&m[1]!=="*"?Number(m[1]):fallback;
}
function scimMeta(type,id,created,updated,version){
  return {resourceType:type,created:new Date(created).toISOString(),lastModified:new Date(updated).toISOString(),version:'W/"'+String(version||1)+'"',location:SCIM_BASE+"/"+type+"s/"+id};
}
function toUser(r){
  const emails=r.email?[{value:r.email,type:"work",primary:true}]:[];
  return {
    schemas:[USER_SCHEMA],id:r.id,externalId:r.external_id||undefined,
    userName:r.user_name,displayName:r.display_name||undefined,
    name:{givenName:r.given_name||undefined,familyName:r.family_name||undefined},
    emails,title:r.title||undefined,active:Boolean(r.active),
    meta:scimMeta("User",r.id,r.created_at,r.updated_at,r.version)
  };
}
async function memberRefs(groupId){
  const x=await rest("organization_scim_group_members",{filters:{group_id:"eq."+groupId},select:"user_id",range:"0-499"});
  return (x.data||[]).map(m=>({value:m.user_id}));
}
async function toGroup(r,includeMembers=true){
  return {
    schemas:[GROUP_SCHEMA],id:r.id,externalId:r.external_id||undefined,
    displayName:r.display_name,
    ...(includeMembers?{members:await memberRefs(r.id)}:{}),
    meta:scimMeta("Group",r.id,r.created_at,r.updated_at,r.version)
  };
}
function parseFilter(raw,allowed){
  if(!raw)return null;
  const m=String(raw).match(/^\s*([A-Za-z][A-Za-z0-9.]*)\s+eq\s+"([^"]*)"\s*$/i);
  if(!m||!allowed.includes(m[1]))throw {status:400,code:"INVALID_FILTER",scimType:"invalidFilter"};
  return {attribute:m[1],value:m[2]};
}
function pageParams(url){
  const start=Math.max(1,Number(url.searchParams.get("startIndex")||1)||1);
  const count=Math.max(0,Math.min(MAX_PAGE,Number(url.searchParams.get("count")||100)||100));
  return {start,count};
}
function primaryEmail(body){
  const emails=Array.isArray(body?.emails)?body.emails:[];
  const p=emails.find(x=>x?.primary===true)||emails[0];
  return String(p?.value||body?.userName||"").trim().toLowerCase();
}
function normalizeBool(v,def=true){
  if(v===undefined||v===null)return def;
  if(typeof v==="boolean")return v;
  return !["false","0","no","off"].includes(String(v).trim().toLowerCase());
}
async function authContext(req){
  const auth=req.headers.get("authorization")||"";
  const m=auth.match(/^Bearer\s+(.+)$/i);
  if(!m)throw {status:401,code:"BEARER_TOKEN_REQUIRED"};
  const hash=await sha256(m[1]);
  return await rpc("trustrelay_scim_resolve_bearer_v14",{p_token_hash:hash});
}
async function oauthToken(req){
  if(req.method!=="POST")return oauth({error:"invalid_request"},405,{allow:"POST"});
  let clientId="",clientSecret="",grantType="";
  const auth=req.headers.get("authorization")||"";
  if(auth.toLowerCase().startsWith("basic ")){
    try{
      const decoded=atob(auth.slice(6));
      const i=decoded.indexOf(":");
      if(i>=0){clientId=decoded.slice(0,i);clientSecret=decoded.slice(i+1)}
    }catch{}
  }
  const ct=(req.headers.get("content-type")||"").toLowerCase();
  if(ct.includes("application/x-www-form-urlencoded")){
    const p=new URLSearchParams(await req.text());
    grantType=p.get("grant_type")||"";
    clientId=clientId||p.get("client_id")||"";
    clientSecret=clientSecret||p.get("client_secret")||"";
  }else{
    const body=await jsonBody(req);
    grantType=String(body.grant_type||"");
    clientId=clientId||String(body.client_id||"");
    clientSecret=clientSecret||String(body.client_secret||"");
  }
  if(grantType!=="client_credentials")return oauth({error:"unsupported_grant_type"},400);
  if(!clientId||!clientSecret)return oauth({error:"invalid_client"},401,{"www-authenticate":'Basic realm="TrustRelay SCIM"'});
  const raw=randomToken("tr_scim_at_",32);
  try{
    const x=await rpc("trustrelay_scim_issue_access_token_v14",{
      p_client_id:clientId,p_secret_hash:await sha256(clientSecret),p_token_hash:await sha256(raw)
    });
    return oauth({access_token:raw,token_type:"Bearer",expires_in:Number(x.expiresIn||3600),scope:"scim"});
  }catch(e){
    return oauth({error:e.code==="INVALID_CLIENT"?"invalid_client":"invalid_request"},e.status===401?401:400,{"www-authenticate":'Basic realm="TrustRelay SCIM"'});
  }
}
async function findUsers(org,url){
  const filter=parseFilter(url.searchParams.get("filter"),["userName","externalId","id"]);
  const {start,count}=pageParams(url);
  const filters={organization_id:"eq."+org};
  if(filter){
    const key=filter.attribute==="userName"?"user_name":filter.attribute==="externalId"?"external_id":"id";
    filters[key]="eq."+(key==="user_name"?filter.value.toLowerCase():filter.value);
  }
  const from=start-1,to=count===0?from:from+count-1;
  const x=await rest("organization_scim_users",{filters,select:"*",range:count===0?"0--1":from+"-"+to,prefer:"count=exact"});
  const rows=(x.data||[]).map(toUser);
  return listResponse(rows,parseTotal(x.headers,rows.length),start);
}
async function getUser(org,id){
  const x=await rest("organization_scim_users",{filters:{organization_id:"eq."+org,id:"eq."+id},select:"*",range:"0-0"});
  return x.data?.[0]||null;
}
async function upsertUser(org,id,body){
  const x=await rpc("trustrelay_scim_upsert_user_v14",{
    p_org_id:org,p_scim_id:id||null,p_external_id:body.externalId||null,
    p_user_name:String(body.userName||primaryEmail(body)||"").trim().toLowerCase(),
    p_email:primaryEmail(body),p_display_name:body.displayName||null,
    p_given_name:body.name?.givenName||null,p_family_name:body.name?.familyName||null,
    p_title:body.title||null,p_active:normalizeBool(body.active,true)
  });
  return x.user;
}
function applyUserPatch(current,operations){
  const body={
    externalId:current.external_id||null,userName:current.user_name,
    displayName:current.display_name||null,
    name:{givenName:current.given_name||null,familyName:current.family_name||null},
    emails:[{value:current.email,type:"work",primary:true}],
    title:current.title||null,active:Boolean(current.active)
  };
  for(const op of operations||[]){
    const kind=String(op?.op||"").toLowerCase();
    const path=String(op?.path||"").trim();
    const value=op?.value;
    if(!["add","replace","remove"].includes(kind))throw {status:400,code:"INVALID_PATCH",scimType:"invalidSyntax"};
    if(!path&&value&&typeof value==="object"&&!Array.isArray(value)){Object.assign(body,value);continue}
    const p=path.toLowerCase();
    if(p==="active")body.active=kind==="remove"?false:normalizeBool(value,false);
    else if(p==="username"){if(kind==="remove")throw {status:400,code:"USERNAME_REQUIRED",scimType:"mutability"};body.userName=String(value||"")}
    else if(p==="displayname")body.displayName=kind==="remove"?null:String(value||"");
    else if(p==="name.givenname")body.name.givenName=kind==="remove"?null:String(value||"");
    else if(p==="name.familyname")body.name.familyName=kind==="remove"?null:String(value||"");
    else if(p==="title")body.title=kind==="remove"?null:String(value||"");
    else if(p==="externalid")body.externalId=kind==="remove"?null:String(value||"");
    else if(p.startsWith("emails")){
      if(kind==="remove")throw {status:400,code:"EMAIL_REQUIRED",scimType:"mutability"};
      const email=Array.isArray(value)?value[0]?.value:value?.value||value;
      body.emails=[{value:String(email||"").trim().toLowerCase(),type:"work",primary:true}];
    }else throw {status:400,code:"PATCH_PATH_UNSUPPORTED",scimType:"invalidPath"};
  }
  return body;
}
async function handleUsers(req,url,org,segments){
  if(segments.length===1){
    if(req.method==="GET")return scim(await findUsers(org,url));
    if(req.method==="POST"){
      const body=await jsonBody(req);
      const row=await upsertUser(org,null,body);
      return scim(toUser({id:row.id,external_id:row.externalId,user_name:row.userName,email:row.email,
        display_name:row.displayName,given_name:row.givenName,family_name:row.familyName,title:row.title,
        active:row.active,version:row.version,created_at:row.createdAt,updated_at:row.updatedAt}),201,
        {location:SCIM_BASE+"/Users/"+row.id});
    }
    return scimError(405,"Method not allowed");
  }
  const id=segments[1];
  const current=await getUser(org,id);
  if(!current)return scimError(404,"User not found");
  if(req.method==="GET")return scim(toUser(current));
  if(req.method==="DELETE"){
    await rpc("trustrelay_scim_delete_user_v14",{p_org_id:org,p_scim_id:id});
    return new Response(null,{status:204,headers:scimHeaders()});
  }
  if(req.method==="PUT"){
    const body=await jsonBody(req);
    const row=await upsertUser(org,id,body);
    return scim(toUser({id:row.id,external_id:row.externalId,user_name:row.userName,email:row.email,
      display_name:row.displayName,given_name:row.givenName,family_name:row.familyName,title:row.title,
      active:row.active,version:row.version,created_at:row.createdAt,updated_at:row.updatedAt}));
  }
  if(req.method==="PATCH"){
    const body=await jsonBody(req);
    if(!Array.isArray(body.Operations))throw {status:400,code:"INVALID_PATCH",scimType:"invalidSyntax"};
    const next=applyUserPatch(current,body.Operations);
    const row=await upsertUser(org,id,next);
    return scim(toUser({id:row.id,external_id:row.externalId,user_name:row.userName,email:row.email,
      display_name:row.displayName,given_name:row.givenName,family_name:row.familyName,title:row.title,
      active:row.active,version:row.version,created_at:row.createdAt,updated_at:row.updatedAt}));
  }
  return scimError(405,"Method not allowed");
}
async function findGroups(org,url){
  const filter=parseFilter(url.searchParams.get("filter"),["displayName","externalId","id"]);
  const {start,count}=pageParams(url);
  const filters={organization_id:"eq."+org};
  if(filter){
    const key=filter.attribute==="displayName"?"display_name":filter.attribute==="externalId"?"external_id":"id";
    filters[key]="eq."+(key==="display_name"?filter.value:filter.value);
  }
  const from=start-1,to=count===0?from:from+count-1;
  const x=await rest("organization_scim_groups",{filters,select:"*",range:count===0?"0--1":from+"-"+to,prefer:"count=exact"});
  const includeMembers=url.searchParams.get("excludedAttributes")!=="members";
  const resources=[];for(const row of x.data||[])resources.push(await toGroup(row,includeMembers));
  return listResponse(resources,parseTotal(x.headers,resources.length),start);
}
async function getGroup(org,id){
  const x=await rest("organization_scim_groups",{filters:{organization_id:"eq."+org,id:"eq."+id},select:"*",range:"0-0"});
  return x.data?.[0]||null;
}
function safeUserId(id){return /^scimusr_[a-f0-9]{32}$/.test(String(id||""))}
async function validateUserIds(org,ids){
  const uniq=[...new Set(ids.filter(Boolean))];
  for(const id of uniq)if(!safeUserId(id))throw {status:400,code:"INVALID_GROUP_MEMBER",scimType:"invalidValue"};
  if(!uniq.length)return [];
  const x=await rest("organization_scim_users",{filters:{organization_id:"eq."+org,id:"in.("+uniq.join(",")+")"},select:"id",range:"0-499"});
  const found=new Set((x.data||[]).map(r=>r.id));
  if(uniq.some(id=>!found.has(id)))throw {status:400,code:"GROUP_MEMBER_NOT_FOUND",scimType:"invalidValue"};
  return uniq;
}
async function replaceGroupMembers(org,groupId,members){
  const ids=await validateUserIds(org,(members||[]).map(x=>String(x?.value||"")));
  await rest("organization_scim_group_members",{method:"DELETE",filters:{group_id:"eq."+groupId},select:"*"});
  if(ids.length)await rest("organization_scim_group_members",{method:"POST",body:ids.map(user_id=>({group_id:groupId,user_id})),select:"*",prefer:"return=minimal"});
}
async function createGroup(org,body){
  const name=String(body.displayName||"").trim();
  if(!name||name.length>160)throw {status:400,code:"GROUP_NAME_INVALID",scimType:"invalidValue"};
  const id="scimgrp_"+crypto.randomUUID().replaceAll("-","");
  const x=await rest("organization_scim_groups",{method:"POST",body:{id,organization_id:org,external_id:body.externalId||null,display_name:name,version:1},select:"*",prefer:"return=representation"});
  await replaceGroupMembers(org,id,body.members||[]);
  await rpc("trustrelay_scim_append_audit_v14",{p_org_id:org,p_event_type:"organization.scim.group_created",p_target_type:"scim_group",p_target_id:id,p_metadata:{displayName:name}});
  return await toGroup(x.data[0]);
}
async function updateGroup(org,id,body,patch=false){
  const current=await getGroup(org,id);if(!current)throw {status:404,code:"GROUP_NOT_FOUND"};
  let name=current.display_name,externalId=current.external_id,replaceMembers=null,addMembers=[],removeMembers=[];
  if(!patch){
    name=String(body.displayName||"").trim();externalId=body.externalId||null;replaceMembers=body.members||[];
  }else{
    for(const op of body.Operations||[]){
      const kind=String(op?.op||"").toLowerCase(),path=String(op?.path||"").trim(),value=op?.value;
      if(!["add","replace","remove"].includes(kind))throw {status:400,code:"INVALID_PATCH",scimType:"invalidSyntax"};
      if(!path&&value&&typeof value==="object"){if(value.displayName!==undefined)name=String(value.displayName);if(value.externalId!==undefined)externalId=value.externalId;continue}
      if(path.toLowerCase()==="displayname")name=kind==="remove"?"":String(value||"");
      else if(path.toLowerCase()==="externalid")externalId=kind==="remove"?null:String(value||"");
      else if(path.toLowerCase()==="members"){
        const vals=Array.isArray(value)?value:[value];
        if(kind==="replace")replaceMembers=vals;else if(kind==="add")addMembers.push(...vals);else replaceMembers=[];
      }else{
        const m=path.match(/^members\[value\s+eq\s+"([^"]+)"\]$/i);
        if(m&&kind==="remove")removeMembers.push({value:m[1]});
        else throw {status:400,code:"PATCH_PATH_UNSUPPORTED",scimType:"invalidPath"};
      }
    }
  }
  if(!name||name.length>160)throw {status:400,code:"GROUP_NAME_INVALID",scimType:"invalidValue"};
  const x=await rest("organization_scim_groups",{method:"PATCH",filters:{organization_id:"eq."+org,id:"eq."+id},body:{display_name:name,external_id:externalId,version:current.version+1,updated_at:new Date().toISOString()},select:"*",prefer:"return=representation"});
  if(replaceMembers!==null)await replaceGroupMembers(org,id,replaceMembers);
  if(addMembers.length){
    const ids=await validateUserIds(org,addMembers.map(x=>String(x?.value||"")));
    if(ids.length)await rest("organization_scim_group_members",{method:"POST",body:ids.map(user_id=>({group_id:id,user_id})),select:"*",prefer:"resolution=merge-duplicates,return=minimal"});
  }
  for(const m of removeMembers){
    if(!safeUserId(m.value))continue;
    await rest("organization_scim_group_members",{method:"DELETE",filters:{group_id:"eq."+id,user_id:"eq."+m.value},select:"*"});
  }
  await rpc("trustrelay_scim_append_audit_v14",{p_org_id:org,p_event_type:"organization.scim.group_updated",p_target_type:"scim_group",p_target_id:id,p_metadata:{displayName:name}});
  return await toGroup(x.data[0]);
}
async function handleGroups(req,url,org,segments){
  if(segments.length===1){
    if(req.method==="GET")return scim(await findGroups(org,url));
    if(req.method==="POST")return scim(await createGroup(org,await jsonBody(req)),201);
    return scimError(405,"Method not allowed");
  }
  const id=segments[1],current=await getGroup(org,id);
  if(!current)return scimError(404,"Group not found");
  if(req.method==="GET")return scim(await toGroup(current,url.searchParams.get("excludedAttributes")!=="members"));
  if(req.method==="DELETE"){
    await rest("organization_scim_groups",{method:"DELETE",filters:{organization_id:"eq."+org,id:"eq."+id},select:"*"});
    await rpc("trustrelay_scim_append_audit_v14",{p_org_id:org,p_event_type:"organization.scim.group_deleted",p_target_type:"scim_group",p_target_id:id,p_metadata:{displayName:current.display_name}});
    return new Response(null,{status:204,headers:scimHeaders()});
  }
  if(req.method==="PUT")return scim(await updateGroup(org,id,await jsonBody(req),false));
  if(req.method==="PATCH"){
    const body=await jsonBody(req);if(!Array.isArray(body.Operations))throw {status:400,code:"INVALID_PATCH",scimType:"invalidSyntax"};
    return scim(await updateGroup(org,id,body,true));
  }
  return scimError(405,"Method not allowed");
}
function serviceProviderConfig(){
  return {schemas:["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    documentationUri:PUBLIC_ORIGIN+"/developers/",
    patch:{supported:true},bulk:{supported:false,maxOperations:0,maxPayloadSize:0},
    filter:{supported:true,maxResults:MAX_PAGE},changePassword:{supported:false},
    sort:{supported:false},etag:{supported:false},
    authenticationSchemes:[
      {type:"oauthbearertoken",name:"OAuth 2.0 Bearer Token",description:"OAuth 2.0 client credentials access token",specUri:"https://www.rfc-editor.org/rfc/rfc6749",primary:true},
      {type:"oauthbearertoken",name:"SCIM Bearer Token",description:"Rotatable TrustRelay SCIM bearer credential",primary:false}
    ],
    meta:{location:SCIM_BASE+"/ServiceProviderConfig",resourceType:"ServiceProviderConfig"}};
}
function resourceTypes(){
  return listResponse([
    {schemas:["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],id:"User",name:"User",endpoint:"/Users",schema:USER_SCHEMA,meta:{location:SCIM_BASE+"/ResourceTypes/User",resourceType:"ResourceType"}},
    {schemas:["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],id:"Group",name:"Group",endpoint:"/Groups",schema:GROUP_SCHEMA,meta:{location:SCIM_BASE+"/ResourceTypes/Group",resourceType:"ResourceType"}}
  ],2,1);
}
function schemas(){
  return listResponse([
    {schemas:["urn:ietf:params:scim:schemas:core:2.0:Schema"],id:USER_SCHEMA,name:"User",description:"TrustRelay institutional user",
      attributes:[
        {name:"userName",type:"string",multiValued:false,required:true,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"server"},
        {name:"externalId",type:"string",multiValued:false,required:false,caseExact:true,mutability:"readWrite",returned:"default",uniqueness:"none"},
        {name:"displayName",type:"string",multiValued:false,required:false,mutability:"readWrite",returned:"default"},
        {name:"name",type:"complex",multiValued:false,required:false,mutability:"readWrite",returned:"default",subAttributes:[{name:"givenName",type:"string",multiValued:false},{name:"familyName",type:"string",multiValued:false}]},
        {name:"emails",type:"complex",multiValued:true,required:false,mutability:"readWrite",returned:"default",subAttributes:[{name:"value",type:"string",multiValued:false},{name:"type",type:"string",multiValued:false},{name:"primary",type:"boolean",multiValued:false}]},
        {name:"title",type:"string",multiValued:false,required:false,mutability:"readWrite",returned:"default"},
        {name:"active",type:"boolean",multiValued:false,required:false,mutability:"readWrite",returned:"default"}
      ],meta:{resourceType:"Schema",location:SCIM_BASE+"/Schemas/"+encodeURIComponent(USER_SCHEMA)}},
    {schemas:["urn:ietf:params:scim:schemas:core:2.0:Schema"],id:GROUP_SCHEMA,name:"Group",description:"TrustRelay institutional group",
      attributes:[
        {name:"displayName",type:"string",multiValued:false,required:true,mutability:"readWrite",returned:"default",uniqueness:"server"},
        {name:"externalId",type:"string",multiValued:false,required:false,mutability:"readWrite",returned:"default"},
        {name:"members",type:"complex",multiValued:true,required:false,mutability:"readWrite",returned:"default",subAttributes:[{name:"value",type:"string",multiValued:false,mutability:"immutable"}]}
      ],meta:{resourceType:"Schema",location:SCIM_BASE+"/Schemas/"+encodeURIComponent(GROUP_SCHEMA)}}
  ],2,1);
}
Deno.serve(async req=>{
  try{
    if(!SUPABASE_URL||!SECRET_KEY||!PUBLIC_ORIGIN)return scimError(503,"SCIM service is not configured");
    if(req.headers.get("origin"))return scimError(403,"Browser-origin SCIM requests are not allowed");
    const path=pathFor(req);
    if(path==="/oauth/token")return await oauthToken(req);

    const ctx=await authContext(req);
    const org=String(ctx.organizationId||"");
    if(!org)return scimError(401,"Invalid SCIM credential");

    const url=new URL(req.url);
    const scimPath=path.startsWith("/scim/v2")?path.slice("/scim/v2".length)||"/":path;
    const segments=scimPath.split("/").filter(Boolean);

    if(req.method==="GET"&&scimPath==="/ServiceProviderConfig")return scim(serviceProviderConfig());
    if(req.method==="GET"&&scimPath==="/ResourceTypes")return scim(resourceTypes());
    if(req.method==="GET"&&segments[0]==="ResourceTypes"&&segments[1]){
      const r=resourceTypes().Resources?.find(x=>x.id===segments[1]);return r?scim(r):scimError(404,"Resource type not found");
    }
    if(req.method==="GET"&&scimPath==="/Schemas")return scim(schemas());
    if(req.method==="GET"&&segments[0]==="Schemas"&&segments[1]){
      const id=decodeURIComponent(segments.slice(1).join("/"));
      const r=schemas().Resources?.find(x=>x.id===id);return r?scim(r):scimError(404,"Schema not found");
    }
    if(segments[0]==="Users")return await handleUsers(req,url,org,segments);
    if(segments[0]==="Groups"){
      if(ctx.groupSyncEnabled===false)return scimError(403,"Group synchronization is disabled");
      return await handleGroups(req,url,org,segments);
    }
    return scimError(404,"SCIM endpoint not found");
  }catch(e){
    const status=Number(e?.status)||500;
    const code=String(e?.code||"SCIM_INTERNAL_ERROR");
    const mapped=status===409?"uniqueness":e?.scimType||null;
    return scimError(status,code.replaceAll("_"," "),mapped);
  }
});