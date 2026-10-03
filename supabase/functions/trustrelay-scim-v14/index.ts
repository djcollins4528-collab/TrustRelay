const URL=(Deno.env.get("SUPABASE_URL")||"").replace(/\/$/,"");
const USER_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:User";
const LIST_SCHEMA="urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERR_SCHEMA="urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_SCHEMA="urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SPC_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const RT_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:ResourceType";
const SCHEMA_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:Schema";

function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function secretKey(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function adminHeaders(){const k=secretKey();const h={apikey:k,"content-type":"application/json",accept:"application/json"};if(k&&!k.startsWith("sb_secret_"))h.authorization="Bearer "+k;return h}
async function parse(r){const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}return{ok:r.ok,status:r.status,data:d,text:t}}
async function rpc(name,payload){const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:adminHeaders(),body:JSON.stringify(payload||{})});const x=await parse(r);if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR",details:x.data};if(x.data?.ok===false)throw{status:Number(x.data?.status)||400,code:x.data?.code||"REQUEST_REJECTED",details:x.data};return x.data}
async function sha256Hex(value){const b=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(String(value||""))));return[...b].map(x=>x.toString(16).padStart(2,"0")).join("")}
function scimHeaders(extra={}){return{"content-type":"application/scim+json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff",...extra}}
function scimResponse(data,status=200,extra={}){return new Response(data===null?null:JSON.stringify(data),{status,headers:scimHeaders(extra)})}
function scimError(status,detail,scimType){const b={schemas:[ERR_SCHEMA],status:String(status),detail:String(detail||"Request failed")};if(scimType)b.scimType=scimType;return scimResponse(b,status,status===401?{"www-authenticate":'Bearer realm="TrustRelay SCIM"'}:{})}
async function jsonBody(req,max=65536){const n=Number(req.headers.get("content-length")||0);if(Number.isFinite(n)&&n>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};const raw=await req.text();if(new TextEncoder().encode(raw).byteLength>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};try{return raw?JSON.parse(raw):{}}catch{throw{status:400,code:"INVALID_JSON",scimType:"invalidSyntax"}}}
function pathParts(url){const parts=new URL(url).pathname.split("/").filter(Boolean);const i=parts.indexOf("trustrelay-scim-v14");return i>=0?parts.slice(i+1).map(decodeURIComponent):[]}
function primaryEmail(user){const emails=Array.isArray(user?.emails)?user.emails:[];const p=emails.find(x=>x?.primary===true)||emails.find(x=>String(x?.type||"").toLowerCase()==="work")||emails[0];return String(p?.value||user?.userName||"").trim().toLowerCase()}
function currentModel(row){return{externalId:row?.externalId||null,userName:row?.userName||"",email:row?.email||row?.userName||"",givenName:row?.givenName||"",familyName:row?.familyName||"",displayName:row?.displayName||"",active:row?.active!==false}}
function applyObject(target,value){if(!value||typeof value!=="object"||Array.isArray(value))return target;if("externalId" in value)target.externalId=value.externalId==null?null:String(value.externalId);if("userName" in value)target.userName=String(value.userName||"");if("displayName" in value)target.displayName=String(value.displayName||"");if("active" in value)target.active=Boolean(value.active);if(value.name&&typeof value.name==="object"){if("givenName" in value.name)target.givenName=String(value.name.givenName||"");if("familyName" in value.name)target.familyName=String(value.name.familyName||"")}if(Array.isArray(value.emails)&&value.emails.length)target.email=primaryEmail(value);return target}
function applyPatch(target,operation){
  const op=String(operation?.op||"").toLowerCase();
  if(!["add","replace","remove"].includes(op))throw{status:400,code:"SCIM_PATCH_OP_INVALID",scimType:"invalidSyntax"};
  const path=String(operation?.path||"").trim(),value=operation?.value;
  if(!path){if(op==="remove")throw{status:400,code:"SCIM_PATCH_PATH_REQUIRED",scimType:"noTarget"};return applyObject(target,value)}
  const p=path.toLowerCase(),remove=op==="remove";
  if(p==="active"){target.active=remove?false:Boolean(value);return target}
  if(p==="username"){target.userName=remove?"":String(value||"");return target}
  if(p==="externalid"){target.externalId=remove?null:String(value||"");return target}
  if(p==="displayname"){target.displayName=remove?"":String(value||"");return target}
  if(p==="name.givenname"){target.givenName=remove?"":String(value||"");return target}
  if(p==="name.familyname"){target.familyName=remove?"":String(value||"");return target}
  if(p==="emails"||p==="emails.value"||/^emails\[type eq ["']work["']\]\.value$/i.test(path)){target.email=remove?"":String(Array.isArray(value)?primaryEmail({emails:value}):value||"");return target}
  throw{status:400,code:"SCIM_PATCH_PATH_UNSUPPORTED",scimType:"noTarget"};
}
function parseFilter(value){
  if(!value)return{attribute:null,value:null};
  const m=String(value).match(/^\s*(userName|externalId|id|emails\.value)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$/i);
  if(!m)throw{status:400,code:"SCIM_FILTER_UNSUPPORTED",scimType:"invalidFilter"};
  const a=m[1].toLowerCase();return{attribute:a==="username"?"userName":a==="externalid"?"externalId":a==="emails.value"?"emails.value":"id",value:m[2].replace(/\\(["\\])/g,"$1")};
}
function versionFor(row){const t=Date.parse(row?.updatedAt||row?.createdAt||"")||0;return 'W/"'+String(t)+'"'}
function userResource(row,base){
  const display=row.displayName||[row.givenName,row.familyName].filter(Boolean).join(" ")||row.userName;
  const u={schemas:[USER_SCHEMA],id:row.id,userName:row.userName,name:{formatted:display},displayName:display,active:row.active!==false,emails:[{value:row.email,type:"work",primary:true}]};
  if(row.externalId)u.externalId=row.externalId;if(row.givenName)u.name.givenName=row.givenName;if(row.familyName)u.name.familyName=row.familyName;
  u.meta={resourceType:"User",created:row.createdAt,lastModified:row.updatedAt,version:versionFor(row),location:base+"/Users/"+encodeURIComponent(row.id)};
  return u;
}
function providerConfig(base){return{schemas:[SPC_SCHEMA],documentationUri:"https://trustrelay-production.onrender.com/developer/",patch:{supported:true},bulk:{supported:false,maxOperations:0,maxPayloadSize:0},filter:{supported:true,maxResults:100},changePassword:{supported:false},sort:{supported:false},etag:{supported:true},authenticationSchemes:[{type:"oauthbearertoken",name:"Bearer Token",description:"TrustRelay organization-scoped SCIM bearer token",specUri:"https://www.rfc-editor.org/rfc/rfc6750",primary:true}],meta:{resourceType:"ServiceProviderConfig",location:base+"/ServiceProviderConfig"}}}
function resourceTypes(base){return{schemas:[LIST_SCHEMA],totalResults:1,startIndex:1,itemsPerPage:1,Resources:[{schemas:[RT_SCHEMA],id:"User",name:"User",endpoint:"/Users",description:"TrustRelay organization member",schema:USER_SCHEMA,meta:{resourceType:"ResourceType",location:base+"/ResourceTypes/User"}}]}}
function userSchema(base){return{schemas:[SCHEMA_SCHEMA],id:USER_SCHEMA,name:"User",description:"TrustRelay SCIM User",attributes:[{name:"userName",type:"string",multiValued:false,required:true,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"server"},{name:"externalId",type:"string",multiValued:false,required:false,caseExact:true,mutability:"readWrite",returned:"default",uniqueness:"none"},{name:"name",type:"complex",multiValued:false,required:false,mutability:"readWrite",returned:"default",subAttributes:[{name:"givenName",type:"string",multiValued:false,required:false,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"none"},{name:"familyName",type:"string",multiValued:false,required:false,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"none"}]},{name:"displayName",type:"string",multiValued:false,required:false,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"none"},{name:"active",type:"boolean",multiValued:false,required:false,mutability:"readWrite",returned:"default"},{name:"emails",type:"complex",multiValued:true,required:false,mutability:"readWrite",returned:"default",subAttributes:[{name:"value",type:"string",multiValued:false,required:true,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"none"},{name:"type",type:"string",multiValued:false,required:false,caseExact:false,mutability:"readWrite",returned:"default",canonicalValues:["work"]},{name:"primary",type:"boolean",multiValued:false,required:false,mutability:"readWrite",returned:"default"}]}],meta:{resourceType:"Schema",location:base+"/Schemas/"+encodeURIComponent(USER_SCHEMA)}}}
async function authenticate(req,tenantKey){
  if(!tenantKey||!/^scim_[A-Za-z0-9_-]{20,80}$/.test(tenantKey))throw{status:401,code:"SCIM_UNAUTHORIZED"};
  const auth=req.headers.get("authorization")||"",m=auth.match(/^Bearer\s+(\S+)$/i);
  if(!m||!/^trscim_[A-Za-z0-9_-]{30,100}$/.test(m[1]))throw{status:401,code:"SCIM_UNAUTHORIZED"};
  const ctx=await rpc("trustrelay_scim_auth_v14",{p_tenant_key:tenantKey,p_token_hash:await sha256Hex(m[1])});
  const ip=(req.headers.get("cf-connecting-ip")||req.headers.get("x-forwarded-for")||"unknown").split(",")[0].trim();
  const rl=await rpc("consume_rate_limit_v05",{p_bucket_key:"scim:"+tenantKey+":"+(await sha256Hex(ip)).slice(0,20),p_limit:1800,p_window_seconds:60}).catch(()=>null);
  const row=Array.isArray(rl)?rl[0]:rl;if(row?.allowed===false)throw{status:429,code:"SCIM_RATE_LIMITED"};
  return ctx;
}
function mapDbError(e){const c=String(e?.code||"");if(c.includes("CONFLICT")||c.includes("UNIQUENESS"))return{status:409,type:"uniqueness"};if(c==="SCIM_USER_NOT_FOUND")return{status:404,type:"noTarget"};if(c==="SCIM_FILTER_UNSUPPORTED")return{status:400,type:"invalidFilter"};if(c==="SCIM_OWNER_DEPROVISION_REQUIRES_TRANSFER")return{status:409,type:"mutability"};if(c==="SCIM_EMAIL_DOMAIN_NOT_VERIFIED")return{status:400,type:"invalidValue"};if(c==="SCIM_DISABLED"||c==="SCIM_UNAUTHORIZED")return{status:401,type:null};return{status:Number(e?.status)||400,type:e?.scimType||null}}

Deno.serve(async req=>{
  try{
    if(!URL||!secretKey())throw{status:503,code:"SCIM_SERVICE_NOT_CONFIGURED"};
    const parts=pathParts(req.url),tenantKey=parts.shift()||"",ctx=await authenticate(req,tenantKey);
    const orgId=String(ctx.organizationId||""),base=URL+"/functions/v1/trustrelay-scim-v14/"+encodeURIComponent(tenantKey);
    const resource=parts[0]||"",id=parts[1]||null,method=req.method.toUpperCase();

    if(method==="GET"&&resource==="ServiceProviderConfig")return scimResponse(providerConfig(base));
    if(method==="GET"&&resource==="ResourceTypes")return scimResponse(resourceTypes(base));
    if(method==="GET"&&resource==="Schemas"){
      if(id&&decodeURIComponent(id)!==USER_SCHEMA)return scimError(404,"Schema not found.");
      return scimResponse(id?userSchema(base):{schemas:[LIST_SCHEMA],totalResults:1,startIndex:1,itemsPerPage:1,Resources:[userSchema(base)]});
    }
    if(resource==="Groups"){
      if(method==="GET")return scimResponse({schemas:[LIST_SCHEMA],totalResults:0,startIndex:1,itemsPerPage:0,Resources:[]});
      return scimError(501,"SCIM group provisioning is not enabled for this TrustRelay organization.");
    }
    if(resource!=="Users")return scimError(404,"SCIM resource not found.");

    if(method==="GET"&&id){
      const x=await rpc("trustrelay_scim_get_user_v14",{p_org_id:orgId,p_scim_id:id});
      const u=userResource(x.user,base);return scimResponse(u,200,{etag:u.meta.version,location:u.meta.location});
    }
    if(method==="GET"){
      const url=new URL(req.url),f=parseFilter(url.searchParams.get("filter"));
      const start=Math.max(1,Number(url.searchParams.get("startIndex")||1)||1),count=Math.max(1,Math.min(100,Number(url.searchParams.get("count")||100)||100));
      const x=await rpc("trustrelay_scim_list_users_v14",{p_org_id:orgId,p_filter_attribute:f.attribute,p_filter_value:f.value,p_start_index:start,p_count:count});
      const users=(x.users||[]).map(u=>userResource(u,base));
      return scimResponse({schemas:[LIST_SCHEMA],totalResults:Number(x.totalResults||0),startIndex:Number(x.startIndex||start),itemsPerPage:users.length,Resources:users});
    }
    if(method==="POST"&&!id){
      const input=await jsonBody(req);
      const x=await rpc("trustrelay_scim_write_user_v14",{p_org_id:orgId,p_mode:"create",p_scim_id:null,p_external_id:input.externalId??null,p_user_name:String(input.userName||""),p_email:primaryEmail(input),p_given_name:String(input.name?.givenName||""),p_family_name:String(input.name?.familyName||""),p_display_name:String(input.displayName||input.name?.formatted||""),p_active:input.active!==false});
      const u=userResource(x.user,base);return scimResponse(u,201,{location:u.meta.location,etag:u.meta.version});
    }
    if(method==="PUT"&&id){
      const input=await jsonBody(req);
      const x=await rpc("trustrelay_scim_write_user_v14",{p_org_id:orgId,p_mode:"replace",p_scim_id:id,p_external_id:input.externalId??null,p_user_name:String(input.userName||""),p_email:primaryEmail(input),p_given_name:String(input.name?.givenName||""),p_family_name:String(input.name?.familyName||""),p_display_name:String(input.displayName||input.name?.formatted||""),p_active:input.active!==false});
      const u=userResource(x.user,base);return scimResponse(u,200,{location:u.meta.location,etag:u.meta.version});
    }
    if(method==="PATCH"&&id){
      const input=await jsonBody(req);
      if(!Array.isArray(input.Operations)||!input.Operations.length)throw{status:400,code:"SCIM_PATCH_OPERATIONS_REQUIRED",scimType:"invalidSyntax"};
      if(Array.isArray(input.schemas)&&!input.schemas.includes(PATCH_SCHEMA))throw{status:400,code:"SCIM_PATCH_SCHEMA_INVALID",scimType:"invalidSyntax"};
      const existing=await rpc("trustrelay_scim_get_user_v14",{p_org_id:orgId,p_scim_id:id});
      let model=currentModel(existing.user);for(const op of input.Operations)model=applyPatch(model,op);
      const x=await rpc("trustrelay_scim_write_user_v14",{p_org_id:orgId,p_mode:"replace",p_scim_id:id,p_external_id:model.externalId,p_user_name:model.userName,p_email:model.email,p_given_name:model.givenName,p_family_name:model.familyName,p_display_name:model.displayName,p_active:model.active});
      const u=userResource(x.user,base);return scimResponse(u,200,{location:u.meta.location,etag:u.meta.version});
    }
    if(method==="DELETE"&&id){
      await rpc("trustrelay_scim_deactivate_user_v14",{p_org_id:orgId,p_scim_id:id});
      return new Response(null,{status:204,headers:{"cache-control":"no-store"}});
    }
    return scimError(405,"Method not allowed.");
  }catch(e){
    const m=mapDbError(e);return scimError(m.status,String(e?.code||e?.message||"SCIM request failed").replaceAll("_"," "),m.type);
  }
});