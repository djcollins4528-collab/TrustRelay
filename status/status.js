const ids=["runtimeStatus","dependencyStatus","apiStatus","scimStatus"];
function setState(id,label,state){
  const el=document.getElementById(id);
  if(!el)return;
  el.textContent=label;
  el.className=state==="operational"?"good":"warn";
}
function timeLabel(value){
  const d=new Date(value);
  return Number.isNaN(d.getTime())?"—":d.toLocaleString();
}
async function refresh(){
  const overall=document.getElementById("overallStatus");
  const message=document.getElementById("statusMessage");
  const last=document.getElementById("lastChecked");
  try{
    const response=await fetch("../status.json",{cache:"no-store",headers:{accept:"application/json"}});
    if(!response.ok)throw new Error("status request failed");
    const data=await response.json();
    const state=String(data?.overall||"unknown");
    const operational=state==="operational";
    overall.textContent=operational?"All monitored systems operational":state==="degraded"?"Service degradation detected":"Service unavailable";
    overall.className=operational?"good":"warn";
    message.textContent=operational
      ?"The production runtime and monitored platform dependency are responding normally."
      :state==="degraded"
        ?"The runtime is reachable, but at least one monitored dependency check is degraded."
        :"The current status check did not confirm normal production operation.";
    const c=data?.components||{};
    setState("runtimeStatus",c.runtime==="operational"?"Operational":c.runtime==="quarantined"?"Quarantined":"Unavailable",c.runtime==="operational"?"operational":"warn");
    setState("dependencyStatus",c.platform==="operational"?"Operational":c.platform==="degraded"?"Degraded":"Unavailable",c.platform==="operational"?"operational":"warn");
    setState("apiStatus",c.partnerApi==="operational"?"Operational":"Degraded",c.partnerApi==="operational"?"operational":"warn");
    setState("scimStatus",c.scim==="operational"?"Operational":"Degraded",c.scim==="operational"?"operational":"warn");
    last.textContent="Last checked: "+timeLabel(data.checkedAt);
  }catch{
    overall.textContent="Status check unavailable";
    overall.className="warn";
    message.textContent="The public status endpoint could not be reached. This does not by itself establish a production outage.";
    for(const id of ids)setState(id,"Unknown","warn");
    last.textContent="Last checked: "+new Date().toLocaleString();
  }
}
refresh();
setInterval(refresh,60000);
