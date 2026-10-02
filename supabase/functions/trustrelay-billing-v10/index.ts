
const URL=Deno.env.get("SUPABASE_URL")||"";
function envJson(name){try{return JSON.parse(Deno.env.get(name)||"{}")}catch{return{}}}
function secretKey(){const x=envJson("SUPABASE_SECRET_KEYS");return x.default||Object.values(x).find(v=>typeof v==="string"&&v)||Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")||""}
function publishableKey(){const x=envJson("SUPABASE_PUBLISHABLE_KEYS");return x.default||Deno.env.get("SUPABASE_ANON_KEY")||""}
const STRIPE_KEY=Deno.env.get("STRIPE_SECRET_KEY")||"";
const STRIPE_WEBHOOK_SECRET=Deno.env.get("STRIPE_WEBHOOK_SECRET")||"";
const PRICE_STARTER=Deno.env.get("STRIPE_PRICE_STARTER")||"";
const PRICE_GROWTH=Deno.env.get("STRIPE_PRICE_GROWTH")||"";
const APP_ORIGIN=(Deno.env.get("TRUSTRELAY_APP_ORIGIN")||"").replace(/\/$/,"");
const EXPECTED_STRIPE_ACCOUNT=URL.includes("msfrbsnihylfynrtdgxe")?"acct_1UM70OGom69ZF9sJ":URL.includes("kdvroylluosshcjmfbfq")?"acct_1UM70VGlBsQ7ehU9":"";
let stripeAccountVerified=false;

function providerConfigured(){return Boolean(STRIPE_KEY&&STRIPE_WEBHOOK_SECRET&&PRICE_STARTER&&PRICE_GROWTH&&APP_ORIGIN)}
function adminHeaders(){
 const k=secretKey(); const h={apikey:k,"content-type":"application/json",accept:"application/json"};
 if(k&&!k.startsWith("sb_secret_"))h.authorization="Bearer "+k;
 return h
}
async function parse(r){const t=await r.text();let d=null;try{d=t?JSON.parse(t):null}catch{}return{ok:r.ok,status:r.status,data:d,text:t}}
async function assertStripeAccount(){
 if(stripeAccountVerified)return;
 if(!STRIPE_KEY||!EXPECTED_STRIPE_ACCOUNT)throw{status:503,code:"BILLING_NOT_CONFIGURED"};
 const r=await fetch("https://api.stripe.com/v1/account",{headers:{authorization:"Bearer "+STRIPE_KEY,accept:"application/json"}});
 const x=await parse(r);
 if(!x.ok)throw{status:502,code:"STRIPE_PROVIDER_ERROR",details:{providerStatus:x.status,type:x.data?.error?.type||null,code:x.data?.error?.code||null}};
 if(x.data?.id!==EXPECTED_STRIPE_ACCOUNT)throw{status:503,code:"STRIPE_ACCOUNT_MISMATCH"};
 stripeAccountVerified=true;
}
async function userFrom(req){
 const auth=req.headers.get("authorization")||"";
 if(!/^Bearer\s+\S+/i.test(auth))throw{status:401,code:"AUTH_REQUIRED"};
 const r=await fetch(URL+"/auth/v1/user",{headers:{apikey:publishableKey(),authorization:auth,accept:"application/json"}});
 if(!r.ok)throw{status:401,code:"INVALID_SESSION"};
 const u=await r.json(); if(!u?.id)throw{status:401,code:"INVALID_SESSION"};
 return {user:u,authorization:auth}
}
async function rpcUser(name,payload,authorization){
 const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:{apikey:publishableKey(),authorization,"content-type":"application/json",accept:"application/json"},body:JSON.stringify(payload||{})});
 const x=await parse(r); if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR"};
 if(x.data?.ok===false)throw{status:Number(x.data?.status)||400,code:x.data?.code||"REQUEST_REJECTED",details:x.data};
 return x.data
}
async function rpcAdmin(name,payload){
 const r=await fetch(URL+"/rest/v1/rpc/"+name,{method:"POST",headers:adminHeaders(),body:JSON.stringify(payload||{})});
 const x=await parse(r); if(!x.ok)throw{status:x.status||500,code:x.data?.code||x.data?.message||"DATABASE_ERROR"};
 if(x.data?.ok===false)throw{status:Number(x.data?.status)||400,code:x.data?.code||"REQUEST_REJECTED",details:x.data};
 return x.data
}
function out(data,status=200){return Response.json(data,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff"}})}
function safeOrigin(req){
 const configured=APP_ORIGIN;
 const origin=req.headers.get("origin")||"";
 if(origin&&origin===configured)return origin;
 return configured
}
async function stripe(path,params){
 if(!STRIPE_KEY)throw{status:503,code:"BILLING_NOT_CONFIGURED"};
 await assertStripeAccount();
 const body=new URLSearchParams();
 for(const [k,v] of Object.entries(params||{})){if(v!==null&&v!==undefined&&v!=="")body.append(k,String(v))}
 const r=await fetch("https://api.stripe.com/v1/"+path,{method:"POST",headers:{authorization:"Bearer "+STRIPE_KEY,"content-type":"application/x-www-form-urlencoded"},body});
 const x=await parse(r);
 if(!x.ok)throw{status:502,code:"STRIPE_PROVIDER_ERROR",details:{providerStatus:x.status,type:x.data?.error?.type||null,code:x.data?.error?.code||null}};
 return x.data
}
function priceFor(plan){if(plan==="starter")return PRICE_STARTER;if(plan==="growth")return PRICE_GROWTH;return""}
async function hmacHex(secret,message){
 const key=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const sig=new Uint8Array(await crypto.subtle.sign("HMAC",key,new TextEncoder().encode(message)));
 return [...sig].map(b=>b.toString(16).padStart(2,"0")).join("")
}
function timingSafeEqualHex(a,b){
 if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;
 let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0
}
async function verifyStripeSignature(raw,header){
 if(!STRIPE_WEBHOOK_SECRET)throw{status:503,code:"BILLING_WEBHOOK_NOT_CONFIGURED"};
 const parts=String(header||"").split(",").map(x=>x.trim());
 const ts=parts.find(x=>x.startsWith("t="))?.slice(2)||"";
 const sigs=parts.filter(x=>x.startsWith("v1=")).map(x=>x.slice(3));
 if(!/^\d+$/.test(ts)||!sigs.length)throw{status:400,code:"STRIPE_SIGNATURE_INVALID"};
 const age=Math.abs(Math.floor(Date.now()/1000)-Number(ts));
 if(age>300)throw{status:400,code:"STRIPE_SIGNATURE_EXPIRED"};
 const expected=await hmacHex(STRIPE_WEBHOOK_SECRET,ts+"."+raw);
 if(!sigs.some(s=>timingSafeEqualHex(s,expected)))throw{status:400,code:"STRIPE_SIGNATURE_INVALID"};
}

Deno.serve(async req=>{
 try{
  if(req.method!=="POST")return out({error:{code:"METHOD_NOT_ALLOWED"}},405);

  const stripeSig=req.headers.get("stripe-signature");
  if(stripeSig){
    const raw=await req.text();
    await verifyStripeSignature(raw,stripeSig);
    let event;try{event=JSON.parse(raw)}catch{throw{status:400,code:"STRIPE_PAYLOAD_INVALID"}}
    if(!event?.id||!event?.type)throw{status:400,code:"STRIPE_EVENT_INVALID"};
    await assertStripeAccount();
    const applied=await rpcAdmin("trustrelay_apply_stripe_event_v10",{
      p_event_id:String(event.id),p_event_type:String(event.type),p_payload_json:raw
    });
    return out({received:true,result:applied});
  }

  const {authorization}=await userFrom(req);
  const input=await req.json();
  const action=String(input.action||"");
  const orgId=String(input.orgId||"").trim();
  if(!orgId)throw{status:400,code:"ORGANIZATION_ID_REQUIRED"};

  if(action==="status"){
    const status=await rpcUser("trustrelay_billing_status_v10",{p_org_id:orgId},authorization);
    return out({...status,providerConfigured:providerConfigured(),checkoutPlans:{starter:Boolean(PRICE_STARTER),growth:Boolean(PRICE_GROWTH)}});
  }

  const perms=await rpcUser("trustrelay_my_org_permissions_v09",{p_org_id:orgId},authorization);
  if(perms?.permissions?.["organization.manage"]!==true)throw{status:403,code:"ORGANIZATION_PERMISSION_DENIED"};

  if(!providerConfigured())throw{status:503,code:"BILLING_NOT_CONFIGURED"};

  if(action==="checkout"){
    const planCode=String(input.planCode||"").trim();
    const price=priceFor(planCode);
    if(!price)throw{status:400,code:"BILLING_PLAN_NOT_CHECKOUT_ENABLED"};

    await rpcUser("trustrelay_select_billing_plan_v10",{p_org_id:orgId,p_plan_code:planCode},authorization);
    const ctx=await rpcAdmin("trustrelay_billing_provider_context_v10",{p_org_id:orgId});
    const origin=safeOrigin(req);

    const params={
      mode:"subscription",
      "line_items[0][price]":price,
      "line_items[0][quantity]":Math.max(1,Number(ctx?.billing?.seatQuantity||1)),
      success_url:origin+"/verifier/?billing=success&session_id={CHECKOUT_SESSION_ID}",
      cancel_url:origin+"/verifier/?billing=cancelled",
      client_reference_id:orgId,
      "metadata[trustrelay_org_id]":orgId,
      "metadata[trustrelay_plan_code]":planCode,
      "subscription_data[metadata][trustrelay_org_id]":orgId,
      "subscription_data[metadata][trustrelay_plan_code]":planCode,
      allow_promotion_codes:"true"
    };
    if(ctx?.billing?.customerId)params.customer=ctx.billing.customerId;
    else if(ctx?.billing?.billingEmail)params.customer_email=ctx.billing.billingEmail;

    const session=await stripe("checkout/sessions",params);
    if(!session?.url)throw{status:502,code:"STRIPE_CHECKOUT_URL_MISSING"};
    return out({url:session.url,sessionId:session.id,planCode},201);
  }

  if(action==="portal"){
    const ctx=await rpcAdmin("trustrelay_billing_provider_context_v10",{p_org_id:orgId});
    if(!ctx?.billing?.customerId)throw{status:409,code:"BILLING_CUSTOMER_NOT_CREATED"};
    const session=await stripe("billing_portal/sessions",{customer:ctx.billing.customerId,return_url:safeOrigin(req)+"/verifier/?billing=return"});
    if(!session?.url)throw{status:502,code:"STRIPE_PORTAL_URL_MISSING"};
    return out({url:session.url});
  }

  throw{status:400,code:"ACTION_INVALID"};
 }catch(e){
  return out({error:{code:e?.code||"INTERNAL_ERROR",details:e?.details||null}},Number(e?.status)||500)
 }
});
