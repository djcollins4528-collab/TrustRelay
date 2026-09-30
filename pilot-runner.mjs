import http from "node:http";
import crypto from "node:crypto";

const SUPABASE_URL = "https://awrradmcwgeepwwdrbzi.supabase.co";
const PUBLISHABLE = "sb_publishable_YHwczFLXsSuJtOQDI_65Lw_dRcyLMjx";
const APP_ORIGIN = "https://trustrelay-app-staging.onrender.com";
const REPRESENTATIVE_EMAIL = "djcollins4528+trustrelay-representative-9f3d7a21@gmail.com";
const sessions = new Map();

function json(res,status,data){
  const body=JSON.stringify(data);
  res.writeHead(status,{
    "content-type":"application/json; charset=utf-8",
    "cache-control":"no-store",
    "x-content-type-options":"nosniff"
  });
  res.end(body);
}
function decodeJwt(token){
  const p=token.split(".")[1];
  if(!p) return {};
  const s=p.replace(/-/g,"+").replace(/_/g,"/");
  return JSON.parse(Buffer.from(s,"base64").toString("utf8"));
}
function fragmentParams(location){
  const hash=(location.split("#")[1]||"");
  return new URLSearchParams(hash);
}
async function sha256(text){
  return crypto.createHash("sha256").update(text).digest("hex");
}
async function edge(name,accessToken,body,method="POST"){
  const headers={apikey:PUBLISHABLE,accept:"application/json"};
  if(accessToken) headers.authorization="Bearer "+accessToken;
  let payload;
  if(body!==undefined){
    headers["content-type"]="application/json";
    payload=JSON.stringify(body);
  }
  const r=await fetch(SUPABASE_URL+"/functions/v1/"+name,{method,headers,body:payload});
  const text=await r.text();
  let data=null; try{data=text?JSON.parse(text):null}catch{data={raw:text.slice(0,500)}}
  return {ok:r.ok,status:r.status,data};
}
async function profile(accessToken){
  const post=await edge("trustrelay-profile-v06",accessToken,{},"POST");
  const get=await edge("trustrelay-profile-v06",accessToken,undefined,"GET");
  return {post,get};
}
async function confirm(role,token){
  if(!["principal","representative"].includes(role)) throw new Error("invalid_role");
  if(!/^[A-Za-z0-9_-]{20,200}$/.test(token)) throw new Error("invalid_token");
  const target=SUPABASE_URL+"/auth/v1/verify?token="+encodeURIComponent(token)+"&type=signup&redirect_to="+encodeURIComponent(APP_ORIGIN);
  const r=await fetch(target,{redirect:"manual"});
  const location=r.headers.get("location")||"";
  const params=fragmentParams(location);
  const access=params.get("access_token");
  const refresh=params.get("refresh_token");
  if(!access){
    return {ok:false,status:r.status,hasLocation:Boolean(location),code:"SESSION_NOT_RETURNED"};
  }
  const claims=decodeJwt(access);
  sessions.set(role,{accessToken:access,refreshToken:refresh||null,userId:claims.sub||null,email:claims.email||null});
  let redirectHost=null;
  try{redirectHost=new URL(location.split("#")[0]).host}catch{}
  return {ok:true,status:r.status,role,userId:claims.sub||null,email:claims.email||null,redirectHost,sessionHeldInMemory:true};
}
async function runPilot(){
  const p=sessions.get("principal"),r=sessions.get("representative");
  if(!p||!r) return {ok:false,code:"BOTH_SESSIONS_REQUIRED",held:[...sessions.keys()]};

  const principalProfile=await profile(p.accessToken);
  const representativeProfile=await profile(r.accessToken);
  if(!principalProfile.post.ok||!representativeProfile.post.ok){
    return {ok:false,stage:"profile_bootstrap",principal:principalProfile.post.status,representative:representativeProfile.post.status};
  }

  const create=await edge("trustrelay-grant-create-v06",p.accessToken,{
    representativeEmail:REPRESENTATIVE_EMAIL,
    allowedActions:["view_balance","view_transactions","pay_bill"],
    prohibitedActions:[],
    resources:["checking:pilot","billpay:pilot"],
    rules:{maxAmount:250,allowedCurrencies:["USD"],requireEvidence:true},
    escalation:{aboveLimit:"ESCALATE"},
    validFrom:new Date(Date.now()-60000).toISOString(),
    validUntil:new Date(Date.now()+7*86400000).toISOString()
  });
  if(!create.ok) return {ok:false,stage:"grant_create",status:create.status,code:create.data?.error?.code||null};

  const grantId=create.data?.grant?.id;
  const inviteToken=create.data?.invitation?.token;
  const invitationId=create.data?.invitation?.id;

  const preview=await edge("trustrelay-invite-preview-v061",r.accessToken,{token:inviteToken});
  if(!preview.ok) return {ok:false,stage:"invite_preview",grantId,invitationId,status:preview.status,code:preview.data?.error?.code||null};

  const accept=await edge("trustrelay-invite-accept-v06",r.accessToken,{token:inviteToken});
  if(!accept.ok) return {ok:false,stage:"invite_accept",grantId,invitationId,status:accept.status,code:accept.data?.error?.code||null};

  const issue=await edge("trustrelay-credential-issue-v06",r.accessToken,{grantId});
  if(!issue.ok) return {ok:false,stage:"credential_issue",grantId,grantStatus:accept.data?.grant?.status,status:issue.status,code:issue.data?.error?.code||null};

  const credentialToken=issue.data?.token;
  const credential=issue.data?.credential||{};
  const before=await edge("trustrelay-credential-verify-v06",null,{token:credentialToken});
  const revoke=await edge("trustrelay-grant-revoke-v06",p.accessToken,{grantId,reason:"v0.6.1 first real two-account pilot"});
  const after=await edge("trustrelay-credential-verify-v06",null,{token:credentialToken});

  const pAfter=await profile(p.accessToken);
  const rAfter=await profile(r.accessToken);
  const fingerprint=(await sha256(credentialToken||"")).slice(0,24);

  const report={
    ok:Boolean(
      before.ok && before.data?.valid===true &&
      revoke.ok &&
      after.ok && after.data?.valid===false
    ),
    identities:{
      principal:{userId:p.userId,email:p.email},
      representative:{userId:r.userId,email:r.email}
    },
    profileBootstrap:{principal:principalProfile.post.ok,representative:representativeProfile.post.ok},
    grant:{
      id:grantId,
      statusAfterAcceptance:accept.data?.grant?.status||null,
      statusAfterRevocation:revoke.data?.grant?.status||null
    },
    invitation:{
      id:invitationId,
      previewPassed:preview.ok,
      principal:preview.data?.principal?.email||preview.data?.principal?.displayName||null,
      allowedActions:preview.data?.grant?.allowed||null,
      resources:preview.data?.grant?.resources||null,
      maxAmount:preview.data?.grant?.rules?.maxAmount??null,
      requireEvidence:preview.data?.grant?.rules?.requireEvidence??null
    },
    credential:{
      id:credential.id||null,
      jti:credential.jti||null,
      kid:credential.kid||null,
      alg:credential.alg||"ES256",
      expiresAt:credential.expiresAt||credential.expires_at||null,
      fingerprint
    },
    verificationBeforeRevocation:{
      requestOk:before.ok,
      valid:before.data?.valid??null,
      reasonCode:before.data?.reasonCode||null
    },
    revocation:{
      requestOk:revoke.ok,
      alreadyRevoked:revoke.data?.alreadyRevoked??false
    },
    verificationAfterRevocation:{
      requestOk:after.ok,
      valid:after.data?.valid??null,
      reasonCode:after.data?.reasonCode||null
    },
    dashboardRefresh:{
      principal:pAfter.get.ok,
      representative:rAfter.get.ok
    }
  };

  sessions.clear();
  return report;
}

const server=http.createServer(async(req,res)=>{
  try{
    const u=new URL(req.url,"http://localhost");
    if(req.method!=="GET") return json(res,405,{error:"METHOD_NOT_ALLOWED"});
    if(u.pathname==="/healthz") return json(res,200,{status:"ok",service:"trustrelay-pilot-runner",sessionsHeld:[...sessions.keys()]});
    if(u.pathname==="/confirm"){
      const result=await confirm(u.searchParams.get("role")||"",u.searchParams.get("token")||"");
      return json(res,result.ok?200:409,result);
    }
    if(u.pathname==="/run"){
      const result=await runPilot();
      return json(res,result.ok?200:409,result);
    }
    return json(res,404,{error:"NOT_FOUND"});
  }catch(e){
    return json(res,500,{ok:false,error:String(e?.message||e)});
  }
});

server.listen(Number(process.env.PORT||10000),"0.0.0.0",()=>{
  console.log(JSON.stringify({event:"trustrelay_pilot_runner_started"}));
});
