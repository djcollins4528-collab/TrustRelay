import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
function envJson(name: string): Record<string,string> {
  try {
    const parsed = JSON.parse(Deno.env.get(name) || "{}");
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch { return {}; }
}
function secretKey() {
  const keys = envJson("SUPABASE_SECRET_KEYS");
  return keys.default || Object.values(keys).find(v => typeof v === "string" && v) || "";
}
const SERVICE_KEY = secretKey();
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function adminHeaders() {
  const headers: Record<string,string> = { apikey: SERVICE_KEY, "content-type": "application/json", accept: "application/json" };
  if (SERVICE_KEY && !SERVICE_KEY.startsWith("sb_secret_")) headers.authorization = "Bearer " + SERVICE_KEY;
  return headers;
}
function json(data: unknown, status = 200) {
  return Response.json(data, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}
function timingSafeEqual(a: string, b: string) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function expectedInternalSecret() {
  if (!SUPABASE_URL || !SERVICE_KEY) throw new Error("EGRESS_RUNTIME_CONFIG_MISSING");
  const response = await fetch(SUPABASE_URL + "/rest/v1/rpc/trustrelay_webhook_egress_secret_v10", {
    method: "POST", headers: adminHeaders(), body: "{}"
  });
  const text = await response.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch {}
  if (!response.ok || data?.ok === false || typeof data?.secret !== "string") throw new Error("EGRESS_SECRET_UNAVAILABLE");
  return data.secret as string;
}
function ipv4ToInt(ip: string) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}
function inV4(ip: string, base: string, bits: number) {
  const value = ipv4ToInt(ip), network = ipv4ToInt(base);
  if (value === null || network === null) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
  return (value & mask) === (network & mask);
}
function isPublicIPv4(ip: string) {
  const blocked: Array<[string,number]> = [
    ["0.0.0.0",8],["10.0.0.0",8],["100.64.0.0",10],["127.0.0.0",8],
    ["169.254.0.0",16],["172.16.0.0",12],["192.0.0.0",24],["192.0.2.0",24],
    ["192.88.99.0",24],["192.168.0.0",16],["198.18.0.0",15],["198.51.100.0",24],
    ["203.0.113.0",24],["224.0.0.0",4],["240.0.0.0",4]
  ];
  return ipv4ToInt(ip) !== null && !blocked.some(([base,bits]) => inV4(ip,base,bits));
}
function isPublicIPv6(ip: string) {
  let value = ip.toLowerCase();
  const zone = value.indexOf("%");
  if (zone >= 0) value = value.slice(0, zone);
  if (value === "::" || value === "::1" || value.startsWith("::ffff:")) return false;
  if (/^f[cd]/.test(value) || /^fe[89ab]/.test(value) || /^ff/.test(value)) return false;
  if (value.startsWith("2001:db8:") || value === "2001:db8::") return false;
  if (value.startsWith("2001:10:") || value.startsWith("2001:20:")) return false;
  const first = Number.parseInt(value.split(":")[0] || "0", 16);
  return Number.isFinite(first) && first >= 0x2000 && first <= 0x3fff;
}
function normalizeHost(hostname: string) {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}
function ipKind(host: string) {
  if (ipv4ToInt(host) !== null) return 4;
  if (host.includes(":")) return 6;
  return 0;
}
async function withTimeout<T>(promise: Promise<T>, ms: number, code: string): Promise<T> {
  let timer: number | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => { timer = setTimeout(() => reject(new Error(code)), ms); })
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
async function resolveAndValidate(hostname: string) {
  const host = normalizeHost(hostname.toLowerCase().replace(/\.$/, ""));
  if (!host || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new Error("WEBHOOK_TARGET_PRIVATE_NETWORK");
  }
  const literal = ipKind(host);
  if (literal === 4) {
    if (!isPublicIPv4(host)) throw new Error("WEBHOOK_TARGET_PRIVATE_NETWORK");
    return [host];
  }
  if (literal === 6) {
    if (!isPublicIPv6(host)) throw new Error("WEBHOOK_TARGET_PRIVATE_NETWORK");
    return [host];
  }
  const [a, aaaa] = await withTimeout(Promise.allSettled([
    Deno.resolveDns(host, "A"), Deno.resolveDns(host, "AAAA")
  ]), 3000, "WEBHOOK_DNS_TIMEOUT");
  const answers: string[] = [];
  if (a.status === "fulfilled") answers.push(...a.value);
  if (aaaa.status === "fulfilled") answers.push(...aaaa.value);
  const unique = [...new Set(answers.map(normalizeHost))];
  if (!unique.length) throw new Error("WEBHOOK_TARGET_DNS_UNRESOLVED");
  for (const ip of unique) {
    const kind = ipKind(ip);
    const allowed = kind === 4 ? isPublicIPv4(ip) : kind === 6 ? isPublicIPv6(ip) : false;
    if (!allowed) throw new Error("WEBHOOK_TARGET_PRIVATE_NETWORK");
  }
  return unique;
}
async function writeAll(conn: Deno.Conn, data: Uint8Array) {
  let offset = 0;
  while (offset < data.length) {
    const written = await conn.write(data.subarray(offset));
    if (written <= 0) throw new Error("WEBHOOK_SOCKET_WRITE_FAILED");
    offset += written;
  }
}
function headerEndIndex(bytes: Uint8Array) {
  for (let i = 0; i + 3 < bytes.length; i++) {
    if (bytes[i]===13 && bytes[i+1]===10 && bytes[i+2]===13 && bytes[i+3]===10) return i + 4;
  }
  return -1;
}
function dechunkExcerpt(body: Uint8Array, maxBytes=4096) {
  let pos=0;
  const out:number[]=[];
  while(pos<body.length && out.length<maxBytes){
    let lineEnd=-1;
    for(let i=pos;i+1<body.length;i++){ if(body[i]===13&&body[i+1]===10){lineEnd=i;break;} }
    if(lineEnd<0) break;
    const sizeText=decoder.decode(body.subarray(pos,lineEnd)).split(";")[0].trim();
    const size=Number.parseInt(sizeText,16);
    if(!Number.isFinite(size)||size<0) break;
    pos=lineEnd+2;
    if(size===0) break;
    const available=Math.min(size,body.length-pos,maxBytes-out.length);
    for(let i=0;i<available;i++) out.push(body[pos+i]);
    if(body.length-pos<size) break;
    pos+=size+2;
  }
  return new Uint8Array(out);
}
async function pinnedHttpsPost(target: URL, pinnedIp: string, headers: Record<string,string>, payload: string) {
  const port = target.port ? Number(target.port) : 443;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("WEBHOOK_PORT_INVALID");
  const tcp = await withTimeout(Deno.connect({ hostname: pinnedIp, port }), 4000, "WEBHOOK_CONNECT_TIMEOUT");
  let tls: Deno.TlsConn | null = null;
  const started=performance.now();
  try {
    tls = await withTimeout(Deno.startTls(tcp,{ hostname: normalizeHost(target.hostname), alpnProtocols:["http/1.1"] }), 5000, "WEBHOOK_TLS_TIMEOUT");
    const path=(target.pathname||"/")+(target.search||"");
    const hostHeader=target.port && target.port!=="443" ? normalizeHost(target.hostname)+":"+target.port : normalizeHost(target.hostname);
    const payloadBytes=encoder.encode(payload);
    const lines=[
      "POST "+path+" HTTP/1.1",
      "Host: "+hostHeader,
      "Content-Type: application/json",
      "Content-Length: "+payloadBytes.length,
      "User-Agent: TrustRelay-Webhook/1.0",
      "X-TrustRelay-Event: "+headers["x-trustrelay-event"],
      "X-TrustRelay-Delivery: "+headers["x-trustrelay-delivery"],
      "X-TrustRelay-Timestamp: "+headers["x-trustrelay-timestamp"],
      "X-TrustRelay-Signature: "+headers["x-trustrelay-signature"],
      "Accept: */*",
      "Connection: close",
      "",
      ""
    ];
    await withTimeout(writeAll(tls,encoder.encode(lines.join("\r\n"))),3000,"WEBHOOK_WRITE_TIMEOUT");
    await withTimeout(writeAll(tls,payloadBytes),3000,"WEBHOOK_WRITE_TIMEOUT");

    const chunks:Uint8Array[]=[];
    let total=0, headerEnd=-1;
    const maxRead=65536;
    while(total<maxRead){
      const buf=new Uint8Array(Math.min(8192,maxRead-total));
      let n:number|null;
      try {
        n=await withTimeout(tls.read(buf),10000,"WEBHOOK_READ_TIMEOUT");
      } catch (readError) {
        const message=readError instanceof Error?readError.message:String(readError);
        if(total>0 && message.includes("close_notify")) break;
        throw readError;
      }
      if(n===null) break;
      if(n<=0) continue;
      chunks.push(buf.slice(0,n)); total+=n;
      const merged=new Uint8Array(total); let off=0;
      for(const c of chunks){merged.set(c,off);off+=c.length;}
      headerEnd=headerEndIndex(merged);
      if(headerEnd>=0 && total-headerEnd>=4096) break;
    }
    const raw=new Uint8Array(total); let off=0; for(const c of chunks){raw.set(c,off);off+=c.length;}
    headerEnd=headerEndIndex(raw);
    if(headerEnd<0) throw new Error("WEBHOOK_RESPONSE_HEADERS_INVALID");
    const headerText=decoder.decode(raw.subarray(0,headerEnd));
    const headerLines=headerText.split("\r\n").filter(Boolean);
    const statusMatch=headerLines[0]?.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})/i);
    if(!statusMatch) throw new Error("WEBHOOK_RESPONSE_STATUS_INVALID");
    const status=Number(statusMatch[1]);
    const responseHeaders=new Map<string,string>();
    for(const line of headerLines.slice(1)){
      const idx=line.indexOf(":"); if(idx>0) responseHeaders.set(line.slice(0,idx).trim().toLowerCase(),line.slice(idx+1).trim());
    }
    let body=raw.subarray(headerEnd);
    if((responseHeaders.get("transfer-encoding")||"").toLowerCase().includes("chunked")) body=dechunkExcerpt(body,4096);
    else if(body.length>4096) body=body.subarray(0,4096);
    return {status,excerpt:decoder.decode(body),durationMs:Math.max(0,Math.round(performance.now()-started))};
  } finally {
    try { tls?.close(); } catch {}
    if (!tls) try { tcp.close(); } catch {}
  }
}

async function jsonBody(req: Request,max=393216){
  const contentLength=Number(req.headers.get("content-length")||0);
  if(Number.isFinite(contentLength)&&contentLength>max)throw Object.assign(new Error("EGRESS_PAYLOAD_TOO_LARGE"),{status:413});
  const raw=await req.text();
  if(encoder.encode(raw).byteLength>max)throw Object.assign(new Error("EGRESS_PAYLOAD_TOO_LARGE"),{status:413});
  try{return raw?JSON.parse(raw):{}}catch{throw Object.assign(new Error("EGRESS_JSON_INVALID"),{status:400})}
}

Deno.serve(async (req: Request) => {
  try {
    if (req.method !== "POST") return json({error:{code:"METHOD_NOT_ALLOWED"}},405);
    const supplied=req.headers.get("x-trustrelay-egress-key")||"";
    const expected=await expectedInternalSecret();
    if(!timingSafeEqual(supplied,expected)) return json({error:{code:"EGRESS_AUTH_INVALID"}},401);

    const input=await jsonBody(req);
    const endpointUrl=String(input?.endpointUrl||"");
    const payloadJson=String(input?.payloadJson||"");
    const eventType=String(input?.eventType||"");
    const deliveryId=String(input?.deliveryId||"");
    const timestamp=String(input?.timestamp||"");
    const signature=String(input?.signature||"");
    if(!endpointUrl||!payloadJson||!eventType||!deliveryId||!/^\d+$/.test(timestamp)||!/^v1=[0-9a-f]{64}$/.test(signature)) {
      return json({error:{code:"EGRESS_REQUEST_INVALID"}},400);
    }
    if([eventType,deliveryId,timestamp,signature].some(v=>/[\r\n]/.test(v))) return json({error:{code:"EGRESS_HEADER_INVALID"}},400);
    if(payloadJson.length>262144) return json({error:{code:"EGRESS_PAYLOAD_TOO_LARGE"}},413);

    let target:URL;
    try{target=new URL(endpointUrl)}catch{return json({error:{code:"WEBHOOK_URL_INVALID"}},400)}
    if(target.protocol!=="https:"||target.username||target.password||!target.hostname) return json({error:{code:"WEBHOOK_URL_INVALID"}},400);

    const ips=await resolveAndValidate(target.hostname);
    const pinnedIp=ips.find(ip=>ipKind(ip)===4)||ips[0];
    const result=await pinnedHttpsPost(target,pinnedIp,{
      "x-trustrelay-event":eventType,
      "x-trustrelay-delivery":deliveryId,
      "x-trustrelay-timestamp":timestamp,
      "x-trustrelay-signature":signature
    },payloadJson);

    if(result.status>=300&&result.status<=399) return json({error:{code:"WEBHOOK_REDIRECT_BLOCKED",status:result.status,durationMs:result.durationMs}},502);
    const outHeaders={"cache-control":"no-store","x-content-type-options":"nosniff","x-trustrelay-egress-ip":pinnedIp,"x-trustrelay-egress-duration-ms":String(result.durationMs)};
    if(result.status===204||result.status===205||result.status===304) return new Response(null,{status:result.status,headers:outHeaders});
    return new Response(result.excerpt,{status:result.status,headers:outHeaders});
  } catch(error) {
    const code=error instanceof Error?error.message:"EGRESS_INTERNAL_ERROR";
    const status=Number((error as any)?.status)||(
      code==="WEBHOOK_TARGET_PRIVATE_NETWORK"?403
      : code.includes("TIMEOUT")?504
      : code==="WEBHOOK_URL_INVALID"||code==="WEBHOOK_PORT_INVALID"||code==="EGRESS_JSON_INVALID"?400
      : 502);
    return json({error:{code:code||"EGRESS_INTERNAL_ERROR"}},status);
  }
});