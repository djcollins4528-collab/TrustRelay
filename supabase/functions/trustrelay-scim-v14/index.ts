const SUPABASE_URL=(Deno.env.get("SUPABASE_URL")||"").replace(/\/$/,"");
const CANONICAL_APP_ORIGIN=SUPABASE_URL.includes("msfrbsnihylfynrtdgxe")
  ?"https://trustrelay-production.onrender.com"
  :SUPABASE_URL.includes("kdvroylluosshcjmfbfq")
    ?"https://trustrelay-staging.onrender.com":"";

const USER_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA="urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERR_SCHEMA="urn:ietf:params:scim:api:messages:2.0:Error";
const PATCH_SCHEMA="urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SPC_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const RT_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:ResourceType";
const SCHEMA_SCHEMA="urn:ietf:params:scim:schemas:core:2.0:Schema";

function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function secretKey(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||""}
function adminHeaders(){
  const k=secretKey();
  const h={apikey:k,"content-type":"application/json",accept:"application/json"};
  if(k&&!k.startsWith("sb_secret_"))h.authorization="Bearer "+k;
  return h;
}
async function parse(r){
  const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}
  return{ok:r.ok,status:r.status,data:d,text:t};
}
async function rpc(name,payload){
  const r=await fetch(SUPABASE_URL+"/rest/v1/rpc/"+name,{
    method:"POST",headers:adminHeaders(),body:JSON.stringify(payload||{})
  });
  const x=await parse(r);
  if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR",details:x.data};
  if(x.data?.ok===false)throw{
    status:Number(x.data?.status)||400,
    code:x.data?.code||"REQUEST_REJECTED",
    details:x.data
  };
  return x.data;
}
async function sha256Hex(value){
  const b=new Uint8Array(await crypto.subtle.digest(
    "SHA-256",new TextEncoder().encode(String(value||""))
  ));
  return[...b].map(x=>x.toString(16).padStart(2,"0")).join("");
}
function scimHeaders(extra={}){
  return{
    "content-type":"application/scim+json; charset=utf-8",
    "cache-control":"no-store",
    "x-content-type-options":"nosniff",
    ...extra
  };
}
function scimResponse(data,status=200,extra={}){
  return new Response(data===null?null:JSON.stringify(data),{
    status,headers:scimHeaders(extra)
  });
}
function scimError(status,detail,scimType,extra={}){
  const body={schemas:[ERR_SCHEMA],status:String(status),detail:String(detail||"Request failed")};
  if(scimType)body.scimType=scimType;
  return scimResponse(body,status,{
    ...(status===401?{"www-authenticate":'Bearer realm="TrustRelay SCIM"'}:{}),
    ...extra
  });
}
async function jsonBody(req,max=65536){
  const n=Number(req.headers.get("content-length")||0);
  if(Number.isFinite(n)&&n>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};
  const raw=await req.text();
  if(new TextEncoder().encode(raw).byteLength>max)throw{status:413,code:"PAYLOAD_TOO_LARGE"};
  try{return raw?JSON.parse(raw):{}}catch{
    throw{status:400,code:"INVALID_JSON",scimType:"invalidSyntax"}
  }
}
function pathParts(url){
  const parts=new URL(url).pathname.split("/").filter(Boolean);
  const i=parts.indexOf("trustrelay-scim-v14");
  return i>=0?parts.slice(i+1).map(decodeURIComponent):[];
}
function primaryEmail(user){
  const emails=Array.isArray(user?.emails)?user.emails:[];
  const p=emails.find(x=>x?.primary===true)
    ||emails.find(x=>String(x?.type||"").toLowerCase()==="work")
    ||emails[0];
  return String(p?.value||user?.userName||"").trim();
}
function scimBoolean(value,defaultValue=true){
  if(value===true||value===false)return value;
  if(value===null||value===undefined||value==="")return defaultValue;
  const v=String(value).trim().toLowerCase();
  if(v==="true"||v==="1")return true;
  if(v==="false"||v==="0")return false;
  throw{status:400,code:"SCIM_BOOLEAN_INVALID",scimType:"invalidValue"};
}
function currentModel(row){
  return{
    externalId:row?.externalId||null,
    userName:row?.userName||"",
    email:row?.email||row?.userName||"",
    givenName:row?.givenName||"",
    familyName:row?.familyName||"",
    displayName:row?.displayName||"",
    title:row?.title||"",
    active:row?.active!==false
  };
}
function applyObject(target,value){
  if(!value||typeof value!=="object"||Array.isArray(value))return target;
  if("externalId" in value)target.externalId=value.externalId==null?null:String(value.externalId);
  if("userName" in value)target.userName=String(value.userName||"");
  if("displayName" in value)target.displayName=String(value.displayName||"");
  if("title" in value)target.title=String(value.title||"");
  if("active" in value)target.active=scimBoolean(value.active,target.active);
  if(value.name&&typeof value.name==="object"){
    if("givenName" in value.name)target.givenName=String(value.name.givenName||"");
    if("familyName" in value.name)target.familyName=String(value.name.familyName||"");
  }
  if(Array.isArray(value.emails)&&value.emails.length)target.email=primaryEmail(value);
  return target;
}
function applyPatch(target,operation){
  const op=String(operation?.op||"").toLowerCase();
  if(!["add","replace","remove"].includes(op))
    throw{status:400,code:"SCIM_PATCH_OP_INVALID",scimType:"invalidSyntax"};
  const path=String(operation?.path||"").trim(),value=operation?.value;
  if(!path){
    if(op==="remove")throw{status:400,code:"SCIM_PATCH_PATH_REQUIRED",scimType:"noTarget"};
    return applyObject(target,value);
  }
  const p=path.toLowerCase(),remove=op==="remove";
  if(p==="active"){target.active=remove?false:scimBoolean(value,target.active);return target}
  if(p==="username"){target.userName=remove?"":String(value||"");return target}
  if(p==="externalid"){target.externalId=remove?null:String(value||"");return target}
  if(p==="displayname"){target.displayName=remove?"":String(value||"");return target}
  if(p==="title"){target.title=remove?"":String(value||"");return target}
  if(p==="name.givenname"){target.givenName=remove?"":String(value||"");return target}
  if(p==="name.familyname"){target.familyName=remove?"":String(value||"");return target}
  if(
    p==="emails"||p==="emails.value"
    ||/^emails\[type eq ["']work["']\]\.value$/i.test(path)
  ){
    target.email=remove?"":String(
      Array.isArray(value)?primaryEmail({emails:value}):value||""
    );
    return target;
  }
  throw{status:400,code:"SCIM_PATCH_PATH_UNSUPPORTED",scimType:"noTarget"};
}

function groupModel(row){
  return{
    externalId:row?.externalId||null,
    displayName:String(row?.displayName||""),
    members:[...new Set((Array.isArray(row?.members)?row.members:[])
      .map(x=>String(x?.value||x||"").trim()).filter(Boolean))]
  };
}
function groupMemberIds(value){
  const list=Array.isArray(value)?value:[];
  return[...new Set(list.map(x=>String(
    typeof x==="string"?x:x?.value||""
  ).trim()).filter(Boolean))];
}
function applyGroupObject(target,value,mode="replace"){
  if(!value||typeof value!=="object"||Array.isArray(value))return target;
  if("externalId" in value)target.externalId=value.externalId==null?null:String(value.externalId);
  if("displayName" in value)target.displayName=String(value.displayName||"");
  if(Array.isArray(value.members)){
    const ids=groupMemberIds(value.members);
    target.members=mode==="add"?[...new Set([...target.members,...ids])]:ids;
  }
  return target;
}
function applyGroupPatch(target,operation){
  const op=String(operation?.op||"").toLowerCase();
  if(!["add","replace","remove"].includes(op))
    throw{status:400,code:"SCIM_PATCH_OP_INVALID",scimType:"invalidSyntax"};
  const path=String(operation?.path||"").trim(),value=operation?.value;
  if(!path){
    if(op==="remove")throw{status:400,code:"SCIM_PATCH_PATH_REQUIRED",scimType:"noTarget"};
    return applyGroupObject(target,value,op==="add"?"add":"replace");
  }
  const p=path.toLowerCase();
  if(p==="displayname"){
    target.displayName=op==="remove"?"":String(value||"");
    return target;
  }
  if(p==="externalid"){
    target.externalId=op==="remove"?null:String(value||"");
    return target;
  }
  if(p==="members"){
    const ids=groupMemberIds(value);
    if(op==="add")target.members=[...new Set([...target.members,...ids])];
    else if(op==="replace")target.members=ids;
    else if(ids.length)target.members=target.members.filter(x=>!ids.includes(x));
    else target.members=[];
    return target;
  }
  const fm=path.match(/^members\[value\s+eq\s+["']([^"']+)["']\]$/i);
  if(fm){
    const memberId=fm[1];
    if(op==="remove")target.members=target.members.filter(x=>x!==memberId);
    else target.members=[...new Set([...target.members,memberId])];
    return target;
  }
  throw{status:400,code:"SCIM_PATCH_PATH_UNSUPPORTED",scimType:"noTarget"};
}
function parseGroupFilter(value){
  if(!value)return{attribute:null,value:null};
  const m=String(value).match(
    /^\s*(displayName|externalId|id)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$/i
  );
  if(!m)throw{status:400,code:"SCIM_FILTER_UNSUPPORTED",scimType:"invalidFilter"};
  const a=m[1].toLowerCase();
  return{
    attribute:a==="displayname"?"displayName":a==="externalid"?"externalId":"id",
    value:m[2].replace(/\\(["\\])/g,"$1")
  };
}

function parseFilter(value){
  if(!value)return{attribute:null,value:null};
  const m=String(value).match(
    /^\s*(userName|externalId|id|emails\.value|emails\[type\s+eq\s+["']work["']\]\.value)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$/i
  );
  if(!m)throw{status:400,code:"SCIM_FILTER_UNSUPPORTED",scimType:"invalidFilter"};
  const a=m[1].toLowerCase();
  return{
    attribute:a==="username"?"userName"
      :a==="externalid"?"externalId"
      :a==="id"?"id":"emails.value",
    value:m[2].replace(/\\(["\\])/g,"$1")
  };
}
function versionFor(row){
  if(Number.isFinite(Number(row?.version))&&Number(row.version)>0)
    return 'W/"'+String(row.version)+'"';
  const t=Date.parse(row?.updatedAt||row?.createdAt||"")||0;
  return 'W/"'+String(t)+'"';
}
function userResource(row,base){
  const display=row.displayName||[row.givenName,row.familyName].filter(Boolean).join(" ")||row.userName;
  const u={
    schemas:[USER_SCHEMA],
    id:row.id,
    userName:row.userName,
    name:{formatted:display},
    displayName:display,
    active:row.active!==false,
    emails:[{value:row.email,type:"work",primary:true}]
  };
  if(row.externalId)u.externalId=row.externalId;
  if(row.givenName)u.name.givenName=row.givenName;
  if(row.familyName)u.name.familyName=row.familyName;
  if(row.title)u.title=row.title;
  u.meta={
    resourceType:"User",
    created:row.createdAt,
    lastModified:row.updatedAt,
    version:versionFor(row),
    location:base+"/Users/"+encodeURIComponent(row.id)
  };
  return u;
}

function groupResource(row,base){
  const g={
    schemas:[GROUP_SCHEMA],
    id:row.id,
    displayName:row.displayName,
    members:(Array.isArray(row.members)?row.members:[]).map(x=>({
      value:String(x?.value||""),
      display:x?.display||undefined,
      "$ref":base+"/Users/"+encodeURIComponent(String(x?.value||""))
    }))
  };
  if(row.externalId)g.externalId=row.externalId;
  g.meta={
    resourceType:"Group",
    created:row.createdAt,
    lastModified:row.updatedAt,
    version:versionFor(row),
    location:base+"/Groups/"+encodeURIComponent(row.id)
  };
  return g;
}

function providerConfig(base){
  return{
    schemas:[SPC_SCHEMA],
    documentationUri:CANONICAL_APP_ORIGIN+"/developers/",
    patch:{supported:true},
    bulk:{supported:false,maxOperations:0,maxPayloadSize:0},
    filter:{supported:true,maxResults:100},
    changePassword:{supported:false},
    sort:{supported:false},
    etag:{supported:true},
    authenticationSchemes:[{
      type:"oauthbearertoken",
      name:"HTTP Bearer Token",
      description:"Rotatable TrustRelay organization-scoped SCIM bearer credential",
      specUri:"https://www.rfc-editor.org/rfc/rfc6750",
      primary:true
    }],
    meta:{resourceType:"ServiceProviderConfig",location:base+"/ServiceProviderConfig"}
  };
}
function resourceTypes(base){
  const Resources=[
    {
      schemas:[RT_SCHEMA],
      id:"User",
      name:"User",
      endpoint:"/Users",
      description:"TrustRelay organization member",
      schema:USER_SCHEMA,
      meta:{resourceType:"ResourceType",location:base+"/ResourceTypes/User"}
    },
    {
      schemas:[RT_SCHEMA],
      id:"Group",
      name:"Group",
      endpoint:"/Groups",
      description:"TrustRelay SCIM group used for enterprise role mapping",
      schema:GROUP_SCHEMA,
      meta:{resourceType:"ResourceType",location:base+"/ResourceTypes/Group"}
    }
  ];
  return{
    schemas:[LIST_SCHEMA],totalResults:Resources.length,startIndex:1,
    itemsPerPage:Resources.length,Resources
  };
}
function userSchema(base){
  return{
    schemas:[SCHEMA_SCHEMA],id:USER_SCHEMA,name:"User",
    description:"TrustRelay SCIM User",
    attributes:[
      {name:"userName",type:"string",multiValued:false,required:true,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"server"},
      {name:"externalId",type:"string",multiValued:false,required:false,caseExact:true,mutability:"readWrite",returned:"default",uniqueness:"none"},
      {name:"name",type:"complex",multiValued:false,required:false,mutability:"readWrite",returned:"default",subAttributes:[
        {name:"givenName",type:"string",multiValued:false,required:false,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"none"},
        {name:"familyName",type:"string",multiValued:false,required:false,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"none"}
      ]},
      {name:"displayName",type:"string",multiValued:false,required:false,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"none"},
      {name:"title",type:"string",multiValued:false,required:false,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"none"},
      {name:"active",type:"boolean",multiValued:false,required:false,mutability:"readWrite",returned:"default"},
      {name:"emails",type:"complex",multiValued:true,required:false,mutability:"readWrite",returned:"default",subAttributes:[
        {name:"value",type:"string",multiValued:false,required:true,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"none"},
        {name:"type",type:"string",multiValued:false,required:false,caseExact:false,mutability:"readWrite",returned:"default",canonicalValues:["work"]},
        {name:"primary",type:"boolean",multiValued:false,required:false,mutability:"readWrite",returned:"default"}
      ]}
    ],
    meta:{resourceType:"Schema",location:base+"/Schemas/"+encodeURIComponent(USER_SCHEMA)}
  };
}

function groupSchema(base){
  return{
    schemas:[SCHEMA_SCHEMA],id:GROUP_SCHEMA,name:"Group",
    description:"TrustRelay SCIM Group",
    attributes:[
      {name:"displayName",type:"string",multiValued:false,required:true,caseExact:false,mutability:"readWrite",returned:"default",uniqueness:"server"},
      {name:"externalId",type:"string",multiValued:false,required:false,caseExact:true,mutability:"readWrite",returned:"default",uniqueness:"none"},
      {name:"members",type:"complex",multiValued:true,required:false,mutability:"readWrite",returned:"default",subAttributes:[
        {name:"value",type:"string",multiValued:false,required:true,caseExact:true,mutability:"immutable",returned:"default",uniqueness:"none"},
        {name:"$ref",type:"reference",referenceTypes:["User"],multiValued:false,required:false,caseExact:true,mutability:"immutable",returned:"default"},
        {name:"display",type:"string",multiValued:false,required:false,caseExact:false,mutability:"readOnly",returned:"default",uniqueness:"none"}
      ]}
    ],
    meta:{resourceType:"Schema",location:base+"/Schemas/"+encodeURIComponent(GROUP_SCHEMA)}
  };
}

async function authenticate(req){
  const auth=req.headers.get("authorization")||"";
  const m=auth.match(/^Bearer\s+(\S+)$/i);
  if(!m||!/^tr_scim_secret_[A-Za-z0-9_-]{40,100}$/.test(m[1]))
    throw{status:401,code:"SCIM_UNAUTHORIZED"};

  const hash=await sha256Hex(m[1]);
  return await rpc("trustrelay_scim_resolve_bearer_v14",{p_token_hash:hash});
}
function mapDbError(e){
  const c=String(e?.code||"");
  if(c.includes("CONFLICT")||c.includes("UNIQUENESS")||c.includes("ALREADY_EXISTS"))
    return{status:409,type:"uniqueness"};
  if(c==="SCIM_USER_NOT_FOUND"||c==="SCIM_GROUP_NOT_FOUND"||c==="SCIM_GROUP_MAPPING_NOT_FOUND")return{status:404,type:"noTarget"};
  if(c==="SCIM_GROUP_MEMBER_NOT_FOUND"||c==="SCIM_GROUP_DISPLAY_NAME_INVALID"||c==="SCIM_GROUP_ROLE_INVALID"||c==="SCIM_GROUP_PRIORITY_INVALID")return{status:400,type:"invalidValue"};
  if(c==="SCIM_GROUP_SYNC_DISABLED")return{status:409,type:"mutability"};
  if(c==="SCIM_FILTER_UNSUPPORTED")return{status:400,type:"invalidFilter"};
  if(c==="SCIM_PRIVILEGED_MEMBER_PROTECTED")return{status:409,type:"mutability"};
  if(c==="SCIM_EMAIL_DOMAIN_NOT_VERIFIED")return{status:403,type:"invalidValue"};
  if(c==="SCIM_NOT_ACTIVE"||c==="INVALID_BEARER_TOKEN"||c==="SCIM_UNAUTHORIZED")
    return{status:401,type:null};
  if(c==="SCIM_RATE_LIMITED")
    return{status:429,type:null,retryAfter:Number(e?.details?.retryAfter)||60};
  return{status:Number(e?.status)||400,type:e?.scimType||null};
}

Deno.serve(async req=>{
  try{
    if(!SUPABASE_URL||!secretKey()||!CANONICAL_APP_ORIGIN)
      throw{status:503,code:"SCIM_SERVICE_NOT_CONFIGURED"};
    if(req.headers.get("origin"))
      throw{status:403,code:"BROWSER_SCIM_FORBIDDEN"};

    const parts=pathParts(req.url);
    const tenantKey=parts.shift()||"";
    if(!/^scim_[A-Za-z0-9_-]{20,80}$/.test(tenantKey))
      throw{status:401,code:"SCIM_UNAUTHORIZED"};

    const ctx=await authenticate(req);
    const orgId=String(ctx.organizationId||"");
    if(!orgId||String(ctx.tenantKey||"")!==tenantKey)
      throw{status:401,code:"SCIM_UNAUTHORIZED"};

    const resource=parts[0]||"";
    const id=parts[1]||null;
    const method=req.method.toUpperCase();
    const base=CANONICAL_APP_ORIGIN+"/scim/v2/"+encodeURIComponent(tenantKey);

    if(method==="GET"&&resource==="ServiceProviderConfig")
      return scimResponse(providerConfig(base));

    if(method==="GET"&&resource==="ResourceTypes"){
      if(id){
        const rt=resourceTypes(base).Resources.find(x=>x.id===id);
        if(!rt)return scimError(404,"Resource type not found.");
        return scimResponse(rt);
      }
      return scimResponse(resourceTypes(base));
    }

    if(method==="GET"&&resource==="Schemas"){
      if(id){
        const schemaId=decodeURIComponent(id);
        if(schemaId===USER_SCHEMA)return scimResponse(userSchema(base));
        if(schemaId===GROUP_SCHEMA)return scimResponse(groupSchema(base));
        return scimError(404,"Schema not found.");
      }
      return scimResponse({
        schemas:[LIST_SCHEMA],totalResults:2,startIndex:1,itemsPerPage:2,
        Resources:[userSchema(base),groupSchema(base)]
      });
    }

    if(resource==="Groups"){
      if(method==="GET"&&id){
        const x=await rpc("trustrelay_scim_get_group_v15",{
          p_org_id:orgId,p_group_id:id
        });
        const g=groupResource(x.group,base);
        return scimResponse(g,200,{etag:g.meta.version,location:g.meta.location});
      }

      if(method==="GET"){
        const url=new URL(req.url),f=parseGroupFilter(url.searchParams.get("filter"));
        const start=Math.max(1,Number(url.searchParams.get("startIndex")||1)||1);
        const count=Math.max(1,Math.min(100,Number(url.searchParams.get("count")||100)||100));
        const x=await rpc("trustrelay_scim_list_groups_v15",{
          p_org_id:orgId,
          p_filter_attribute:f.attribute,
          p_filter_value:f.value,
          p_start_index:start,
          p_count:count
        });
        const groups=(x.groups||[]).map(g=>groupResource(g,base));
        return scimResponse({
          schemas:[LIST_SCHEMA],
          totalResults:Number(x.totalResults||0),
          startIndex:Number(x.startIndex||start),
          itemsPerPage:groups.length,
          Resources:groups
        });
      }

      if(method==="POST"&&!id){
        const input=await jsonBody(req);
        const x=await rpc("trustrelay_scim_upsert_group_v15",{
          p_org_id:orgId,
          p_group_id:null,
          p_external_id:input.externalId??null,
          p_display_name:String(input.displayName||""),
          p_member_ids:groupMemberIds(input.members)
        });
        const g=groupResource(x.group,base);
        return scimResponse(g,201,{location:g.meta.location,etag:g.meta.version});
      }

      if(method==="PUT"&&id){
        const input=await jsonBody(req);
        const x=await rpc("trustrelay_scim_upsert_group_v15",{
          p_org_id:orgId,
          p_group_id:id,
          p_external_id:input.externalId??null,
          p_display_name:String(input.displayName||""),
          p_member_ids:groupMemberIds(input.members)
        });
        const g=groupResource(x.group,base);
        return scimResponse(g,200,{location:g.meta.location,etag:g.meta.version});
      }

      if(method==="PATCH"&&id){
        const input=await jsonBody(req);
        if(!Array.isArray(input.Operations)||!input.Operations.length)
          throw{status:400,code:"SCIM_PATCH_OPERATIONS_REQUIRED",scimType:"invalidSyntax"};
        if(Array.isArray(input.schemas)&&!input.schemas.includes(PATCH_SCHEMA))
          throw{status:400,code:"SCIM_PATCH_SCHEMA_INVALID",scimType:"invalidSyntax"};

        const existing=await rpc("trustrelay_scim_get_group_v15",{
          p_org_id:orgId,p_group_id:id
        });
        let model=groupModel(existing.group);
        for(const op of input.Operations)model=applyGroupPatch(model,op);

        const x=await rpc("trustrelay_scim_upsert_group_v15",{
          p_org_id:orgId,
          p_group_id:id,
          p_external_id:model.externalId,
          p_display_name:model.displayName,
          p_member_ids:model.members
        });
        const g=groupResource(x.group,base);
        return scimResponse(g,200,{location:g.meta.location,etag:g.meta.version});
      }

      if(method==="DELETE"&&id){
        await rpc("trustrelay_scim_delete_group_v15",{
          p_org_id:orgId,p_group_id:id
        });
        return new Response(null,{status:204,headers:{
          "cache-control":"no-store",
          "x-content-type-options":"nosniff"
        }});
      }

      return scimError(405,"Method not allowed.");
    }

    if(resource!==""&&resource!=="Users")
      return scimError(404,"SCIM resource not found.");

    if(resource===""){
      if(method!=="GET")return scimError(405,"Method not allowed.");
      return scimResponse(providerConfig(base));
    }

    if(method==="GET"&&id){
      const x=await rpc("trustrelay_scim_get_user_v14",{
        p_org_id:orgId,p_scim_id:id
      });
      const u=userResource(x.user,base);
      return scimResponse(u,200,{etag:u.meta.version,location:u.meta.location});
    }

    if(method==="GET"){
      const url=new URL(req.url),f=parseFilter(url.searchParams.get("filter"));
      const start=Math.max(1,Number(url.searchParams.get("startIndex")||1)||1);
      const count=Math.max(1,Math.min(100,Number(url.searchParams.get("count")||100)||100));
      const x=await rpc("trustrelay_scim_list_users_v14",{
        p_org_id:orgId,
        p_filter_attribute:f.attribute,
        p_filter_value:f.value,
        p_start_index:start,
        p_count:count
      });
      const users=(x.users||[]).map(u=>userResource(u,base));
      return scimResponse({
        schemas:[LIST_SCHEMA],
        totalResults:Number(x.totalResults||0),
        startIndex:Number(x.startIndex||start),
        itemsPerPage:users.length,
        Resources:users
      });
    }

    if(method==="POST"&&!id){
      const input=await jsonBody(req);
      const x=await rpc("trustrelay_scim_upsert_user_v14",{
        p_org_id:orgId,
        p_scim_id:null,
        p_external_id:input.externalId??null,
        p_user_name:String(input.userName||""),
        p_email:primaryEmail(input),
        p_display_name:String(input.displayName||input.name?.formatted||""),
        p_given_name:String(input.name?.givenName||""),
        p_family_name:String(input.name?.familyName||""),
        p_title:String(input.title||""),
        p_active:scimBoolean(input.active,true)
      });
      const u=userResource(x.user,base);
      return scimResponse(u,201,{location:u.meta.location,etag:u.meta.version});
    }

    if(method==="PUT"&&id){
      const input=await jsonBody(req);
      const x=await rpc("trustrelay_scim_upsert_user_v14",{
        p_org_id:orgId,
        p_scim_id:id,
        p_external_id:input.externalId??null,
        p_user_name:String(input.userName||""),
        p_email:primaryEmail(input),
        p_display_name:String(input.displayName||input.name?.formatted||""),
        p_given_name:String(input.name?.givenName||""),
        p_family_name:String(input.name?.familyName||""),
        p_title:String(input.title||""),
        p_active:scimBoolean(input.active,true)
      });
      const u=userResource(x.user,base);
      return scimResponse(u,200,{location:u.meta.location,etag:u.meta.version});
    }

    if(method==="PATCH"&&id){
      const input=await jsonBody(req);
      if(!Array.isArray(input.Operations)||!input.Operations.length)
        throw{status:400,code:"SCIM_PATCH_OPERATIONS_REQUIRED",scimType:"invalidSyntax"};
      if(Array.isArray(input.schemas)&&!input.schemas.includes(PATCH_SCHEMA))
        throw{status:400,code:"SCIM_PATCH_SCHEMA_INVALID",scimType:"invalidSyntax"};

      const existing=await rpc("trustrelay_scim_get_user_v14",{
        p_org_id:orgId,p_scim_id:id
      });
      let model=currentModel(existing.user);
      for(const op of input.Operations)model=applyPatch(model,op);

      const x=await rpc("trustrelay_scim_upsert_user_v14",{
        p_org_id:orgId,
        p_scim_id:id,
        p_external_id:model.externalId,
        p_user_name:model.userName,
        p_email:model.email,
        p_display_name:model.displayName,
        p_given_name:model.givenName,
        p_family_name:model.familyName,
        p_title:model.title,
        p_active:model.active
      });
      const u=userResource(x.user,base);
      return scimResponse(u,200,{location:u.meta.location,etag:u.meta.version});
    }

    if(method==="DELETE"&&id){
      await rpc("trustrelay_scim_delete_user_v14",{
        p_org_id:orgId,p_scim_id:id
      });
      return new Response(null,{status:204,headers:{
        "cache-control":"no-store",
        "x-content-type-options":"nosniff"
      }});
    }

    return scimError(405,"Method not allowed.");
  }catch(e){
    const m=mapDbError(e);
    return scimError(
      m.status,
      String(e?.code||e?.message||"SCIM request failed").replaceAll("_"," "),
      m.type,
      m.retryAfter?{"retry-after":String(m.retryAfter)}:{}
    );
  }
});
