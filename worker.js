export class GroupDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(req) {
    const { action, group, payload } = await req.json();
    if (action !== "commit") return new Response("Unknown DO action", { status: 400 });

    return this.state.blockConcurrencyWhile(async () => {
      // 一次性临时凭证：和提交记录放在同一个串行区内核销，保证只能用一次
      const grant = payload.grant ? String(payload.grant).trim() : "";
      let grantRecord = null;
      if (grant) {
        const raw = await this.env.GROUP_KV.get("grant:" + grant);
        try { grantRecord = raw ? JSON.parse(raw) : null; } catch (_) {}
        if (!grantRecord || grantRecord.used) {
          return Response.json({ ok: false, reason: "临时凭证无效或已被使用" });
        }
      }

      const nonce = payload.claims && payload.claims.nonce;
      if (nonce) {
        if (await this.state.storage.get("nonce:" + nonce)) {
          return Response.json({ ok: false, reason: "该上传凭证已被使用" });
        }
        const cutoff = Date.now() - 24 * 3600 * 1000;
        const old = await this.state.storage.list({ prefix: "nonce:" });
        for (const [k, v] of old) if (v < cutoff) await this.state.storage.delete(k);
      }

      const raw = await this.env.GROUP_KV.get(`grp:${group}`);
      const g = raw ? JSON.parse(raw) : { members: [], files: [] };

      for (const sid of payload.sids) {
        if (g.members.includes(sid)) {
          return Response.json({ ok: false, reason: `学号${sid}已在该组` });
        }
        const bound = await this.env.GROUP_KV.get(`sid:${sid}`);
        if (bound && bound !== group) {
          return Response.json({ ok: false, reason: `学号${sid}已在「${bound}」组` });
        }
      }

      g.members = [...new Set([...g.members, ...payload.sids])];
      g.files.push(payload.file);

      await this.env.GROUP_KV.put(`grp:${group}`, JSON.stringify(g));
      for (const sid of payload.sids) {
        await this.env.GROUP_KV.put(`sid:${sid}`, group);
      }
      if (nonce) await this.state.storage.put("nonce:" + nonce, Date.now());
      if (grant) {
        await this.env.GROUP_KV.put("grant:" + grant, JSON.stringify({
          created: grantRecord.created || Date.now(),
          note: grantRecord.note || "",
          used: true,
          usedAt: Date.now(),
          usedBy: group
        }));
      }
      return Response.json({ ok: true });
    });
  }
}

function b64urlEncode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - b64.length % 4) % 4));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(env, message) {
  const secret = env.UPLOAD_SECRET || env.ADMIN_PASS || "";
  if (!secret) throw new Error("缺少 UPLOAD_SECRET 或 ADMIN_PASS 配置");
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
                                            { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return toHex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}

function timingSafeEqual(a, b) {
  const x = String(a), y = String(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0);
  return diff === 0;
}

async function signPayload(env, payload) {
  const encoded = b64urlEncode(JSON.stringify(payload));
  return encoded + "." + (await hmacHex(env, encoded));
}

async function readPayload(env, token) {
  if (typeof token !== "string" || !token) return null;
  const dot = token.lastIndexOf(".");
  if (dot < 1) return null;
  const encoded = token.slice(0, dot);
  const expected = await hmacHex(env, encoded);
  if (!timingSafeEqual(token.slice(dot + 1), expected)) return null;
  try {
    const payload = JSON.parse(b64urlDecode(encoded));
    if (!payload || typeof payload !== "object") return null;
    if (typeof payload.exp !== "number" || Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

async function makeAdminToken(env) {
  return signPayload(env, { scope: "admin", exp: Date.now() + 2 * 3600 * 1000 });
}

async function adminOk(req, env, token) {
  if (await authOk(req, env)) return true;
  const payload = await readPayload(env, token);
  return !!(payload && payload.scope === "admin");
}

function escapeHtml(s) {
  return String(s == null ? "" : s)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function defaultSids() {
  const out = [];
  for (let i = 1; i <= 48; i++) out.push(String(i));
  return out;
}

function getExpectedSids(cfg) {
  const raw = String((cfg && cfg.expectedSids) || "").trim();
  if (!raw) return defaultSids();
  const out = [];
  const seen = new Set();
  const add = function (s) {
    if (!seen.has(s)) { seen.add(s); out.push(s); }
  };
  for (const part of raw.split(/[,，、\s]+/)) {
    if (!part) continue;
    const range = part.match(/^(\d{1,10})[~～](\d{1,10})$/);
    if (range) {
      const a = Number(range[1]), b = Number(range[2]);
      if (a >= 1 && b >= a && b - a <= 10000) {
        for (let i = a; i <= b; i++) add(String(i));
        continue;
      }
    }
    if (/^\d{1,10}$/.test(part) && Number(part) >= 1) add(String(Number(part)));
  }
  return out.length ? out : defaultSids();
}

function isTestSid(sid, cfg) {
  return String(sid).trim() === "-1" && !!(cfg && cfg.testMode);
}

const ALLOWED_EXT = new Set([
  "mp4", "mov", "mkv", "avi", "webm", "m4v", "mp3", "wav", "m4a", "aac", "flac", "ogg",
  "png", "jpg", "jpeg", "gif", "webp", "ppt", "pptx", "pdf", "doc", "docx", "zip", "rar", "7z", "txt", "bin"
]);

function safeExt(filename) {
  const m = String(filename || "").match(/\.([A-Za-z0-9]{1,8})$/);
  const raw = m ? m[1] : "bin";
  return ALLOWED_EXT.has(raw.toLowerCase()) ? raw : "bin";
}

function buildObjectKey(group, sids, filename) {
  return group + "/" + sids.join("-") + "." + safeExt(filename);
}

function encodeStorageKey(key) {
  return String(key).split("/").map(encodeURIComponent).join("/");
}

async function listGroupKeys(env) {
  const out = [];
  let cursor = null;
  for (;;) {
    const opts = { prefix: "grp:" };
    if (cursor) opts.cursor = cursor;
    const page = await env.GROUP_KV.list(opts);
    for (const k of page.keys) out.push(k.name);
    if (page.list_complete || !page.cursor) break;
    cursor = page.cursor;
  }
  return out;
}

function storageClient(store) {
  if (store.backend === "b2") {
    return new S3Client({
      endpoint: store.b2.s3Endpoint || `https://s3.${store.b2.region}.backblazeb2.com`,
      bucket: store.b2.bucketName,
      region: store.b2.region,
      accessKeyId: store.b2.applicationKeyId,
      secretAccessKey: store.b2.applicationKey
    });
  }
  if (store.backend === "s3") return new S3Client(store.s3);
  return null;
}

async function deleteStorageObject(store, key) {
  if (store.backend === "webdav") {
    const dav = store.webdav;
    const base = String(dav.baseUrl || "").replace(/\/+$/, "");
    if (!base) return;
    try {
      await fetch(base + "/" + encodeStorageKey(key), {
        method: "DELETE",
        headers: { Authorization: "Basic " + btoa(dav.username + ":" + dav.password) }
      });
    } catch (_) {}
    return;
  }
  const client = storageClient(store);
  if (client) await client.deleteObject(key).catch(() => {});
}

function normalizeGrant(s) {
  return String(s == null ? "" : s).trim().toLowerCase();
}

async function getGrant(env, id) {
  if (!id) return null;
  const raw = await env.GROUP_KV.get("grant:" + id);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) { return null; }
}

async function listGrants(env) {
  const out = [];
  let cursor = null;
  for (;;) {
    const opts = { prefix: "grant:" };
    if (cursor) opts.cursor = cursor;
    const page = await env.GROUP_KV.list(opts);
    for (const k of page.keys) {
      let meta = {};
      try { meta = JSON.parse(await env.GROUP_KV.get(k.name) || "{}"); } catch (_) {}
      out.push({ id: k.name.slice("grant:".length), ...meta });
    }
    if (page.list_complete || !page.cursor) break;
    cursor = page.cursor;
  }
  return out.sort((a, b) => (b.created || 0) - (a.created || 0));
}

// 临时凭证只绕过「截止时间」；管理员手动关闭提交仍一律拒绝
async function assertSubmissionOpen(env, hasGrant) {
  const cfg = await getConfig(env);
  if (!cfg.submissionOpen) return "当前已关闭提交";
  const deadline = await getDeadline(env);
  if (hasGrant !== true && deadline !== null && Date.now() >= deadline) return "提交已截止";
  return null;
}

function byteStream(bytes) {
  return new ReadableStream({
    start(c) { c.enqueue(bytes); c.close(); }
  });
}

function isValidStudentId(sid) {
  if (typeof sid !== "string") return false;
  sid = sid.trim();
  if (!/^\d{1,10}$/.test(sid)) return false;
  const n = Number(sid);
  return n >= 1 && n <= 9999999999;
}

function isValidGroupName(name) {
  if (typeof name !== "string") return false;
  name = name.trim();
  if (!name || name.length > 50) return false;
  return /^[\u4e00-\u9fa5a-zA-Z0-9 _\-]+$/.test(name);
}

async function getConfig(env) {
  const raw = await env.GROUP_KV.get("config");
  const def = {
    groupMode: true, groupSize: 4, submitTypes: ["video"], submissionOpen: true,
    expectedSids: "", testMode: false
  };
  if (!raw) return def;
  try { return { ...def, ...JSON.parse(raw) }; } catch { return def; }
}

async function getStorageConfig(env) {
  const raw = await env.GROUP_KV.get("storage");
  const def = {
    backend: "s3",
    s3: { endpoint: "", bucket: "", region: "", accessKeyId: "", secretAccessKey: "" },
    webdav: { baseUrl: "", username: "", password: "" },
    b2: { applicationKeyId: "", applicationKey: "", bucketName: "", region: "us-west-004", s3Endpoint: "" }
  };
  if (!raw) return def;
  try {
    const parsed = JSON.parse(raw);
    return {
      backend: ["s3", "webdav", "b2"].includes(parsed.backend) ? parsed.backend : "s3",
      s3: { ...def.s3, ...(parsed.s3 || {}) },
      webdav: { ...def.webdav, ...(parsed.webdav || {}) },
      b2: { ...def.b2, ...(parsed.b2 || {}) }
    };
  } catch { return def; }
}

async function getNameMap(env) {
  const raw = await env.GROUP_KV.get("namemap");
  if (!raw) return {};
  try {
    const o = JSON.parse(raw);
    const out = {};
    if (o && typeof o === "object") {
      for (const k of Object.keys(o)) {
        const sid = String(k).trim();
        const nm = String(o[k] == null ? "" : o[k]).trim().replace(/[\/\\:*?"<>|\s]/g, "_");
        if (sid && nm) out[sid] = nm.slice(0, 30);
      }
    }
    return out;
  } catch { return {}; }
}

function labelOf(map, sid) {
  const s = String(sid);
  return map[sid] ? s + "_" + map[sid] : s;
}

function buildDownloadName(nmap, key, originalName) {
  var seg = String(key || "").split("/");
  if (seg.length < 2) return null;
  var group = seg.slice(0, -1).join("/").replace(/[\\/:*?"<>|]/g, "_");
  var base = seg[seg.length - 1] || "";
  if (!group || !base) return null;

  var ext = "";
  var em = base.match(/\.([A-Za-z0-9]{1,8})$/);
  if (em) ext = em[1];
  else {
    var em2 = String(originalName || "").match(/\.([A-Za-z0-9]{1,8})$/);
    if (em2) ext = em2[1];
  }
  if (!ext) ext = "bin";

  var stem = base.replace(/\.[A-Za-z0-9]{1,8}$/, "").replace(/[_-]\d{13}$/, "");
  var parts = stem.split(/[-_]/).filter(function (p) { return /^\d{1,10}$/.test(p); });
  if (/^-\d{1,10}$/.test(stem)) parts = [stem];
  else if (stem.charAt(0) === "-" && parts.length) parts[0] = "-" + parts[0];
  if (!parts.length) return null;
  if (group === "personal") parts = [parts[0]];

  return parts.map(function (s) { return labelOf(nmap, s); }).join("-") + "." + ext;
}

async function getDeadline(env) {
  const v = await env.GROUP_KV.get("deadline");
  if (!v) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

class S3Client {
  constructor(cfg) {
    this.endpoint = (cfg.endpoint || "").replace(/\/+$/, "");
    this.bucket = cfg.bucket;
    this.accessKey = (cfg.accessKeyId || "").trim();
    this.secretKey = (cfg.secretAccessKey || "").trim();
    this.region = (cfg.region || "us-west-004").trim();
  }

  encodeKey(key) {
    return encodeURIComponent(key).replace(/%2F/g, "/");
  }

  strictEncode(str) {
    return encodeURIComponent(str).replace(/[!'()*]/g,
                                           c => "%" + c.charCodeAt(0).toString(16).toUpperCase());
  }

  async sha256(message) {
    const msgBuffer = typeof message === "string"
    ? new TextEncoder().encode(message) : message;
    const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
    return [...new Uint8Array(hashBuffer)]
    .map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async hmac(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
      "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    return crypto.subtle.sign("HMAC", cryptoKey, message);
  }

  bytesToHex(bytes) {
    return [...new Uint8Array(bytes)]
    .map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async getSignatureKey(dateStamp) {
    const kDate = await this.hmac(
      new TextEncoder().encode("AWS4" + this.secretKey),
                                  new TextEncoder().encode(dateStamp)
    );
    const kRegion = await this.hmac(kDate, new TextEncoder().encode(this.region));
    const kService = await this.hmac(kRegion, new TextEncoder().encode("s3"));
    const kSigning = await this.hmac(kService, new TextEncoder().encode("aws4_request"));
    return kSigning;
  }

  async testConnection() {
    try {
      const now = new Date();
      const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
      const dateStamp = amzDate.slice(0, 8);
      const baseUrl = this.endpoint.replace(/\/+$/, "");
      const url = new URL(`${baseUrl}/${this.bucket}/`);
      const host = url.host;
      const canonicalUri = url.pathname;

      const actualQuery = "list-type=2&max-keys=1";
      const queryParams = { "list-type": "2", "max-keys": "1" };
      const canonicalQueryString = Object.keys(queryParams).sort()
      .map(k => `${this.strictEncode(k)}=${this.strictEncode(queryParams[k])}`)
      .join("&");

      const canonicalHeaders = `host:${host}\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:${amzDate}\n`;
      const signedHeaders = "host;x-amz-content-sha256;x-amz-date";

      const canonicalRequest = [
        "GET", canonicalUri, canonicalQueryString,
        canonicalHeaders, signedHeaders, "UNSIGNED-PAYLOAD"
      ].join("\n");

      const hashedCr = await this.sha256(canonicalRequest);
      const scope = `${dateStamp}/${this.region}/s3/aws4_request`;
      const stringToSign = [
        "AWS4-HMAC-SHA256", amzDate, scope, hashedCr
      ].join("\n");

      const signingKey = await this.getSignatureKey(dateStamp);
      const sigBuf = await this.hmac(signingKey, new TextEncoder().encode(stringToSign));
      const signature = this.bytesToHex(sigBuf);

      const authHeader =
      `AWS4-HMAC-SHA256 ` +
      `Credential=${this.accessKey}/${scope}, ` +
      `SignedHeaders=${signedHeaders}, ` +
      `Signature=${signature}`;

      const res = await fetch(`${baseUrl}${canonicalUri}?${actualQuery}`, {
        method: "GET",
        headers: {
          "Authorization": authHeader,
          "x-amz-date": amzDate,
          "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        }
      });

      const body = await res.text();
      if (res.status === 200) return { ok: true, msg: "✅ B2 (S3兼容) 连接成功" };
      return { ok: false, msg: `❌ B2 返回 ${res.status}:\n${body.slice(0, 800)}` };
    } catch (e) {
      return { ok: false, msg: `❌ B2 连接异常: ${e.message || "未知错误"}` };
    }
  }

  async putObject(key, body, contentType) {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
    const dateStamp = amzDate.slice(0, 8);
    const encodedKey = this.encodeKey(key);
    const canonicalUri = `/${this.bucket}/${encodedKey}`;
    const host = new URL(this.endpoint).host;
    const credential = `${this.accessKey}/${dateStamp}/${this.region}/s3/aws4_request`;

    const canonicalHeaders = `host:${host}\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:${amzDate}\n`;
    const signedHeaders = "host;x-amz-content-sha256;x-amz-date";

    const canonicalRequest = [
      "PUT", canonicalUri, "",
      canonicalHeaders, signedHeaders, "UNSIGNED-PAYLOAD"
    ].join("\n");

    const hashedCr = await this.sha256(canonicalRequest);
    const scope = `${dateStamp}/${this.region}/s3/aws4_request`;
    const stringToSign = [
      "AWS4-HMAC-SHA256", amzDate, scope, hashedCr
    ].join("\n");

    const signingKey = await this.getSignatureKey(dateStamp);
    const sigBuf = await this.hmac(signingKey, new TextEncoder().encode(stringToSign));
    const signature = this.bytesToHex(sigBuf);

    const authHeader =
    `AWS4-HMAC-SHA256 ` +
    `Credential=${credential}, ` +
    `SignedHeaders=${signedHeaders}, ` +
    `Signature=${signature}`;

    const url = `${this.endpoint}${canonicalUri}`;

    return fetch(url, {
      method: "PUT",
      headers: {
        "Authorization": authHeader,
        "x-amz-date": amzDate,
        "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
        "Content-Type": contentType || "application/octet-stream",
      },
      body: body,
      duplex: "half",
    });
  }

  async deleteObject(key) {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
    const dateStamp = amzDate.slice(0, 8);
    const encodedKey = this.encodeKey(key);
    const canonicalUri = `/${this.bucket}/${encodedKey}`;
    const host = new URL(this.endpoint).host;
    const credential = `${this.accessKey}/${dateStamp}/${this.region}/s3/aws4_request`;

    const rawParams = {
      "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
      "X-Amz-Credential": credential,
      "X-Amz-Date": amzDate,
      "X-Amz-SignedHeaders": "host",
    };
    const canonicalQueryString = Object.keys(rawParams).sort()
    .map(k => `${this.strictEncode(k)}=${this.strictEncode(rawParams[k])}`)
    .join("&");

    const canonicalRequest = [
      "DELETE", canonicalUri, canonicalQueryString,
      `host:${host}`, "", "host", "UNSIGNED-PAYLOAD"
    ].join("\n");

    const stringToSign = [
      "AWS4-HMAC-SHA256", amzDate,
      `${dateStamp}/${this.region}/s3/aws4_request`,
      await this.sha256(canonicalRequest),
    ].join("\n");

    const signingKey = await this.getSignatureKey(dateStamp);
    const sigBuf = await this.hmac(signingKey, new TextEncoder().encode(stringToSign));
    const signature = this.bytesToHex(sigBuf);

    const wireQuery = Object.keys(rawParams).sort()
    .map(k => `${this.strictEncode(k)}=${this.strictEncode(rawParams[k])}`)
    .join("&");

    const finalUrl = `${this.endpoint}${canonicalUri}?${wireQuery}&X-Amz-Signature=${signature}`;
    return fetch(finalUrl, { method: "DELETE" });
  }

  async getSignedDownloadUrl(key, expiresIn = 3600, filename) {
    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
    const dateStamp = amzDate.slice(0, 8);
    const encodedKey = this.encodeKey(key);
    const canonicalUri = `/${this.bucket}/${encodedKey}`;
    const host = new URL(this.endpoint).host;
    const credential = `${this.accessKey}/${dateStamp}/${this.region}/s3/aws4_request`;

    const rawParams = {
      "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
      "X-Amz-Credential": credential,
      "X-Amz-Date": amzDate,
      "X-Amz-Expires": expiresIn.toString(),
      "X-Amz-SignedHeaders": "host",
    };
    if (filename) {
      rawParams["response-content-disposition"] =
      `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`;
    }

    const canonicalQueryString = Object.keys(rawParams).sort()
    .map(k => `${this.strictEncode(k)}=${this.strictEncode(rawParams[k])}`)
    .join("&");

    const canonicalRequest = [
      "GET", canonicalUri, canonicalQueryString,
      `host:${host}`, "", "host", "UNSIGNED-PAYLOAD"
    ].join("\n");

    const stringToSign = [
      "AWS4-HMAC-SHA256", amzDate,
      `${dateStamp}/${this.region}/s3/aws4_request`,
      await this.sha256(canonicalRequest),
    ].join("\n");

    const signingKey = await this.getSignatureKey(dateStamp);
    const sigBuf = await this.hmac(signingKey, new TextEncoder().encode(stringToSign));
    const signature = this.bytesToHex(sigBuf);

    const wireQuery = Object.keys(rawParams).sort()
    .map(k => `${this.strictEncode(k)}=${this.strictEncode(rawParams[k])}`)
    .join("&");

    return `${this.endpoint}${canonicalUri}?${wireQuery}&X-Amz-Signature=${signature}`;
  }
}

function basicChallenge() {
  return new Response("Unauthorized", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="admin"' },
  });
}

async function authOk(req, env) {
  const auth = req.headers.get("Authorization") || "";
  const [scheme, b64] = auth.split(" ");
  if (scheme !== "Basic" || !b64) return false;
  let decoded;
  try { decoded = atob(b64); } catch { return false; }
  const i = decoded.indexOf(":");
  if (i < 0) return false;
  return timingSafeEqual(decoded.slice(0, i), env.ADMIN_USER || "") &&
  timingSafeEqual(decoded.slice(i + 1), env.ADMIN_PASS || "");
}

const uiCss = `:root{
  --bg:#eef3fb;
  --ink:#1b2740;
  --muted:#687892;
  --line:rgba(255,255,255,.62);
  --glass:rgba(255,255,255,.60);
  --glass-2:rgba(255,255,255,.80);
  --accent:#4f6bed;
  --accent-soft:rgba(79,107,237,.12);
  --teal:#12a89a;
  --teal-soft:rgba(18,168,154,.13);
  --danger:#dc5a68;
  --danger-soft:rgba(220,90,104,.11);
  --warn:#d99327;
  --ok:#159a68;
  --radius:18px;
  --shadow:0 10px 36px rgba(28,48,92,.10);
  --shadow-sm:0 2px 10px rgba(28,48,92,.07);
  --page-grad:linear-gradient(135deg,#eaf0ff 0%,#f5f9ff 42%,#eaf8f6 100%);
  --aurora-1:radial-gradient(circle,#9db4ff,#c7d8ff 60%,transparent 72%);
  --aurora-2:radial-gradient(circle,#8fe3d5,#c9f3ec 60%,transparent 72%);
  --input-bg:rgba(255,255,255,.72);
  --input-border:rgba(27,39,64,.14);
  --input-focus-bg:rgba(255,255,255,.92);
  --btn-bg:rgba(255,255,255,.70);
  --btn-border:rgba(79,107,237,.20);
  --btn-hover:rgba(255,255,255,.90);
  --chip-bg:rgba(79,107,237,.13);
  --chip-border:rgba(79,107,237,.14);
  --warn-bg:rgba(255,247,230,.72);
  --warn-border:rgba(217,147,39,.28);
  --warn-ink:#8a6218;
  --danger-border:rgba(220,90,104,.14);
  --pre-bg:rgba(255,255,255,.68);
  --dash-border:rgba(27,39,64,.12);
  --shadow-hover:rgba(28,48,92,.13);
  --code-bg:rgba(27,39,64,.07);
  --code-ink:#3a4a68;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{
  margin:0;
  position:relative;
  min-height:100vh;
  font-family:system-ui,-apple-system,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  color:var(--ink);
  background:var(--page-grad);
  -webkit-font-smoothing:antialiased;
  line-height:1.6;
}
.aurora{position:absolute;inset:0;min-height:100vh;overflow:hidden;pointer-events:none;z-index:0}
.aurora span{position:absolute;display:block;border-radius:50%;filter:blur(90px);opacity:.55}
.aurora span:first-child{width:520px;height:520px;top:-160px;left:-120px;background:var(--aurora-1)}
.aurora span:last-child{width:480px;height:480px;bottom:-180px;right:-120px;background:var(--aurora-2)}
.shell{position:relative;z-index:1;max-width:580px;margin:0 auto;padding:48px 20px 40px}
.shell-wide{max-width:960px}
.hero{margin:0 0 26px}
.brand{display:inline-flex;align-items:center;gap:8px;font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-weight:700;margin-bottom:14px}
.brand .dot{width:8px;height:8px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--teal));box-shadow:0 0 0 4px var(--accent-soft)}
h1,h2,h3{margin:0;font-weight:700;letter-spacing:-.02em;line-height:1.3}
h1{font-size:30px}
h2{font-size:19px}
h3{font-size:16px}
.lede{margin:8px 0 0;color:var(--muted);font-size:14px}
.section-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:700;letter-spacing:.06em;padding:4px 10px;border-radius:999px;background:var(--teal-soft);color:var(--teal);border:1px solid rgba(18,168,154,.18)}
.glass{
  background:var(--glass);
  -webkit-backdrop-filter:blur(20px) saturate(170%);
  backdrop-filter:blur(20px) saturate(170%);
  border:1px solid var(--line);
  border-radius:var(--radius);
  box-shadow:var(--shadow);
}
.card{padding:24px;margin:0 0 18px}
.notice{padding:16px 18px;margin:0 0 18px;font-size:15px}
.notice-warn{background:var(--warn-bg);border-color:var(--warn-border);color:var(--warn-ink)}
.foot{text-align:center;color:var(--muted);font-size:12px;margin-top:22px;letter-spacing:.04em}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline;text-underline-offset:3px}
p{margin:10px 0}
label{cursor:pointer}
input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]),select,textarea{
  font-family:inherit;font-size:14px;color:var(--ink);
  background:var(--input-bg);
  border:1px solid var(--input-border);
  border-radius:11px;
  padding:9px 12px;
  outline:none;
  transition:border-color .18s,box-shadow .18s,background .18s;
}
input:not([type="hidden"]):focus,select:focus,textarea:focus{
  border-color:rgba(79,107,237,.55);
  box-shadow:0 0 0 4px var(--accent-soft);
  background:var(--input-focus-bg);
}
input[type="checkbox"],input[type="radio"]{accent-color:var(--accent);width:15px;height:15px;vertical-align:-2px}
input[type="file"]{padding:7px}
input[type="file"]::file-selector-button{font-family:inherit;font-size:12.5px;font-weight:650;padding:7px 12px;margin-right:10px;border-radius:9px;border:1px solid var(--btn-border);background:var(--accent-soft);color:var(--accent);cursor:pointer}
textarea{width:100%;resize:vertical;line-height:1.6}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  font-family:inherit;font-size:13px;font-weight:650;line-height:1.4;
  padding:9px 16px;border-radius:11px;
  border:1px solid var(--btn-border);
  background:var(--btn-bg);
  color:var(--ink);
  cursor:pointer;
  box-shadow:var(--shadow-sm);
  transition:transform .15s,box-shadow .15s,background .15s,border-color .15s;
  -webkit-appearance:none;appearance:none;
}
.btn:hover{transform:translateY(-1px);box-shadow:0 6px 18px var(--shadow-hover);text-decoration:none}
.btn:active{transform:translateY(0)}
.btn-primary{background:var(--accent);border-color:transparent;color:#fff;box-shadow:0 6px 18px rgba(79,107,237,.28)}
.btn-primary:hover{background:#435fd8}
.btn-ok{background:var(--ok);border-color:transparent;color:#fff;box-shadow:0 6px 18px rgba(21,154,104,.24)}
.btn-ok:hover{background:#128a5d}
.btn-danger{background:var(--danger);border-color:transparent;color:#fff;box-shadow:0 6px 18px rgba(220,90,104,.22)}
.btn-danger:hover{background:#c94b59}
.btn-ghost{background:var(--btn-bg);border-color:var(--btn-border);color:var(--muted)}
.btn-ghost:hover{color:var(--ink);background:var(--btn-hover)}
.btn-danger-ghost{background:var(--danger-soft);border-color:var(--danger-border);color:var(--danger)}
.btn-block{display:flex;width:100%;margin-top:6px;padding:12px 18px;font-size:15px}
.btn-xs{padding:5px 10px;font-size:12px;border-radius:9px;box-shadow:none}
.btn-icon{padding:2px 7px;font-size:12px;border-radius:8px;box-shadow:none}
.sid-input{display:block;width:100%;margin:0 0 10px}
#box form p{margin:0 0 14px}
#box input:not([type="hidden"]),#box select{width:100%}
#box select{appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--muted) 50%),linear-gradient(135deg,var(--muted) 50%,transparent 50%);background-position:calc(100% - 18px) 52%,calc(100% - 13px) 52%;background-size:5px 5px,5px 5px;background-repeat:no-repeat;padding-right:34px}
.progress{margin-top:14px;font-size:13px;color:var(--accent);min-height:20px;font-weight:600}
.msg{font-weight:650;min-height:22px;margin-top:10px}
.msg.err{color:var(--danger)}
#status details{border-top:1px dashed var(--dash-border);padding:10px 0}
#status details:first-child{border-top:0}
#status summary{cursor:pointer;font-weight:650;font-size:14px;color:var(--ink);list-style:none}
#status summary::-webkit-details-marker{display:none}
#status summary::before{content:"›";display:inline-block;margin-right:8px;color:var(--accent);transition:transform .18s}
#status details[open] summary::before{transform:rotate(90deg)}
#status ul{margin:8px 0 0;padding-left:18px;color:var(--muted);font-size:13px}
#status p{color:var(--muted);font-size:14px;margin:6px 0}
.admin h1{font-size:28px;margin-bottom:6px}
.admin h2{font-size:22px;margin-bottom:10px}
.admin h3{font-size:16px;margin:0 0 12px;display:flex;align-items:center;flex-wrap:wrap;gap:6px}
.admin p{line-height:1.75}
.admin a{text-decoration:none}
.admin a:hover{text-decoration:underline;text-underline-offset:3px}
.admin .toplink{display:inline-flex;align-items:center;padding:5px 11px;margin:0 6px 6px 0;border-radius:999px;background:var(--glass);border:1px solid var(--line);font-size:13px;font-weight:600;box-shadow:var(--shadow-sm)}
.admin .toplink:hover{background:var(--btn-hover);text-decoration:none}
.admin .meta{color:var(--muted);font-size:13px}
.admin .stat{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0}
.admin .stat > p{margin:0;padding:12px 16px;flex:1 1 200px;background:var(--glass);border:1px solid var(--line);border-radius:14px;-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);font-size:14px;font-weight:600}
.admin b[style*="color:#c00"]{color:var(--danger) !important}
.admin p[style*="color:#c00"]{color:var(--danger) !important;font-size:12.5px;background:var(--danger-soft);border:1px solid var(--danger-border);padding:9px 13px;border-radius:12px;line-height:1.8}
.admin span[style*="color:#888"]{color:var(--muted) !important}
.admin span[style*="color:green"]{color:var(--ok) !important;font-size:12px !important;font-weight:700}
.admin span[style*="color:#999"]{color:var(--muted) !important}
.admin a[style*="margin-right"]{margin-right:0 !important}
.admin input:not([type="hidden"]):not([type="checkbox"]):not([type="radio"]),.admin select,.admin textarea{
  background:var(--input-bg) !important;
  border:1px solid var(--input-border) !important;
  border-radius:11px !important;
  padding:9px 12px !important;
  color:var(--ink) !important;
  box-shadow:none !important;
  font-family:inherit !important;
  font-size:14px !important;
}
.admin textarea{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace !important;line-height:1.6 !important}
.admin fieldset{
  background:var(--glass) !important;
  border:1px solid var(--line) !important;
  border-radius:var(--radius) !important;
  -webkit-backdrop-filter:blur(18px) saturate(160%);
  backdrop-filter:blur(18px) saturate(160%);
  padding:20px !important;
  margin:16px 0 !important;
  box-shadow:var(--shadow);
}
.admin legend{padding:0 10px;font-weight:700;font-size:14px}
.admin fieldset p{margin:10px 0}
.admin fieldset label{margin-right:14px !important}
.admin #zbar{
  background:var(--glass) !important;
  border:1px solid var(--line) !important;
  border-radius:var(--radius) !important;
  padding:20px !important;
  margin:16px 0 !important;
  box-shadow:var(--shadow) !important;
  -webkit-backdrop-filter:blur(18px) saturate(160%);
  backdrop-filter:blur(18px) saturate(160%);
}
.admin #zbar > b{display:block;margin-bottom:12px;font-size:15px}
.admin #zcnt{margin-left:10px;color:var(--muted);font-size:13px;font-weight:600}
.admin #zmsg{margin-top:10px;color:var(--danger);font-size:13px;min-height:18px}
.admin div[style*="border:1px solid #ddd"]{
  background:var(--glass) !important;
  border:1px solid var(--line) !important;
  border-radius:var(--radius) !important;
  padding:20px !important;
  margin:16px 0 !important;
  box-shadow:var(--shadow) !important;
  -webkit-backdrop-filter:blur(18px) saturate(160%);
  backdrop-filter:blur(18px) saturate(160%);
}
.admin div[style*="border:1px solid #ff9900"]{
  background:var(--warn-bg) !important;
  border:1px solid var(--warn-border) !important;
  border-radius:var(--radius) !important;
  padding:20px !important;
  margin:16px 0 !important;
  box-shadow:var(--shadow) !important;
  -webkit-backdrop-filter:blur(18px) saturate(160%);
  backdrop-filter:blur(18px) saturate(160%);
}
.admin div[style*="border:1px dashed #ccc"]{
  background:var(--glass) !important;
  border:1px dashed var(--dash-border) !important;
  border-radius:var(--radius) !important;
  padding:20px !important;
  margin:16px 0 !important;
  color:var(--muted) !important;
  -webkit-backdrop-filter:blur(18px);
  backdrop-filter:blur(18px);
}
.admin div[style*="background:#f5f5f5"]{
  background:var(--accent-soft) !important;
  border-radius:12px !important;
  padding:12px 14px !important;
  margin-bottom:12px !important;
  font-size:13px;
}
.admin span[style*="background:#e0e8ff"]{
  display:inline-flex;align-items:center;gap:4px;
  background:var(--chip-bg) !important;
  border:1px solid var(--chip-border);
  border-radius:999px !important;
  padding:3px 10px !important;
  margin:2px 4px !important;
  font-size:12px;font-weight:600;
}
.admin ul{list-style:none;margin:6px 0 0 !important;padding-left:0 !important}
.admin li{padding:9px 2px;border-bottom:1px dashed var(--dash-border);font-size:13px;display:flex;align-items:center;flex-wrap:wrap;gap:4px}
.admin li:last-child{border-bottom:0}
.admin li a{font-weight:600}
.admin pre#out{
  margin-top:14px !important;padding:14px !important;
  background:var(--pre-bg) !important;
  border:1px solid var(--line);border-radius:12px;
  font-size:13px;white-space:pre-wrap;word-break:break-word;
}
.admin hr{border:0;border-top:1px dashed var(--dash-border);margin:20px 0}
.egg{
  --ink:#f1f5ff;--muted:#a9b9dc;
  --glass:rgba(255,255,255,.075);--glass-2:rgba(255,255,255,.13);
  --line:rgba(255,255,255,.17);
  --accent:#9db2ff;--accent-soft:rgba(157,178,255,.20);
  --teal:#63e0c8;--teal-soft:rgba(99,224,200,.18);
  --shadow:0 12px 44px rgba(4,10,32,.34);
  background:linear-gradient(135deg,#151b38 0%,#2b2354 46%,#0c4b58 100%);
  color:var(--ink);
}
.egg .aurora span{opacity:.5}
.egg .aurora span:first-child{background:radial-gradient(circle,#6b62d6,#3b3d86 60%,transparent 72%)}
.egg .aurora span:last-child{background:radial-gradient(circle,#2f9c9a,#1c5e70 60%,transparent 72%)}
.egg .glass{box-shadow:var(--shadow)}
.egg .brand{color:var(--muted)}
.egg .lede,.egg .note{color:var(--muted)}
.egg .card{background:var(--glass);border-color:var(--line)}
.egg .card h2{font-size:16px;margin:0 0 14px}
.egg .opts{display:flex;flex-wrap:wrap;gap:8px}
.egg .btn.opt{background:rgba(255,255,255,.06);border-color:rgba(255,255,255,.22);color:var(--ink);font-weight:550;padding:8px 14px;border-radius:999px;box-shadow:none}
.egg .btn.opt:hover{background:rgba(255,255,255,.14)}
.egg .btn.opt.on{background:var(--teal);border-color:transparent;color:#082b2a;font-weight:750;box-shadow:0 6px 20px rgba(99,224,200,.28)}
.egg textarea{background:rgba(255,255,255,.07) !important;border-color:rgba(255,255,255,.20) !important;color:var(--ink) !important;min-height:96px}
.egg textarea::placeholder{color:rgba(169,185,220,.65)}
.egg textarea:focus{border-color:rgba(99,224,200,.6) !important;box-shadow:0 0 0 4px var(--teal-soft) !important;background:rgba(255,255,255,.10) !important}
.egg #verdict{display:none;margin:16px 0;padding:18px;white-space:pre-line;line-height:1.85;font-size:14px;background:var(--glass);border:1px solid var(--line);border-left:3px solid var(--teal);border-radius:14px;-webkit-backdrop-filter:blur(16px);backdrop-filter:blur(16px)}
.egg .back{display:inline-flex;align-items:center;margin-top:14px;font-size:13px;color:var(--muted);font-weight:600}
.egg .note{font-size:12.5px;line-height:1.85;margin-top:20px}
.egg code{background:rgba(255,255,255,.11);padding:2px 7px;border-radius:6px;font-size:12px;color:#cfe0ff}
@media (max-width:640px){
  .shell{padding:28px 14px 28px}
  h1{font-size:25px}
  .card{padding:18px}
  .admin .stat > p{flex:1 1 100%}
  .btn{font-size:12.5px;padding:8px 13px}
}
@media (prefers-reduced-motion:reduce){
  *{transition:none !important;animation:none !important;scroll-behavior:auto !important}
}
:root[data-theme="dark"]{
  color-scheme:dark;
  --bg:#0a1020;
  --ink:#e9effc;
  --muted:#97a9c9;
  --line:rgba(255,255,255,.10);
  --glass:rgba(22,31,52,.66);
  --glass-2:rgba(32,44,70,.88);
  --accent:#8fa3ff;
  --accent-soft:rgba(143,163,255,.18);
  --teal:#4fdac2;
  --teal-soft:rgba(79,218,194,.16);
  --danger:#f07c8a;
  --danger-soft:rgba(240,124,138,.14);
  --warn:#e6b25c;
  --ok:#3fc48d;
  --shadow:0 12px 40px rgba(0,0,0,.38);
  --shadow-sm:0 2px 12px rgba(0,0,0,.28);
  --page-grad:linear-gradient(135deg,#0a1226 0%,#101b31 44%,#0a2229 100%);
  --aurora-1:radial-gradient(circle,#3c4a9c,#25316e 60%,transparent 72%);
  --aurora-2:radial-gradient(circle,#1d7d7c,#124a55 60%,transparent 72%);
  --input-bg:rgba(255,255,255,.055);
  --input-border:rgba(255,255,255,.13);
  --input-focus-bg:rgba(255,255,255,.10);
  --btn-bg:rgba(255,255,255,.075);
  --btn-border:rgba(255,255,255,.14);
  --btn-hover:rgba(255,255,255,.14);
  --chip-bg:rgba(143,163,255,.16);
  --chip-border:rgba(143,163,255,.22);
  --warn-bg:rgba(76,58,26,.62);
  --warn-border:rgba(230,178,92,.26);
  --warn-ink:#f0d39a;
  --danger-border:rgba(240,124,138,.24);
  --pre-bg:rgba(255,255,255,.06);
  --dash-border:rgba(255,255,255,.13);
  --shadow-hover:rgba(0,0,0,.30);
  --code-bg:rgba(255,255,255,.09);
  --code-ink:#cddcff;
}
:root[data-theme="dark"] .aurora span{opacity:.42}
:root[data-theme="dark"] .btn-primary,
:root[data-theme="dark"] .btn-ok,
:root[data-theme="dark"] .btn-danger{color:#0d1424}
:root[data-theme="dark"] .pill{border-color:rgba(79,218,194,.24)}
:root[data-theme="dark"] input:not([type="hidden"]),
:root[data-theme="dark"] select,
:root[data-theme="dark"] textarea{color-scheme:dark}
:root[data-theme="dark"] input[type="datetime-local"]::-webkit-calendar-picker-indicator{filter:invert(.85)}
.theme-toggle{
  position:fixed;top:16px;right:16px;z-index:60;
  width:38px;height:38px;display:flex;align-items:center;justify-content:center;
  font-size:13px;font-weight:700;line-height:1;cursor:pointer;
  border-radius:12px;border:1px solid var(--line);
  background:var(--glass);color:var(--ink);
  box-shadow:var(--shadow-sm);
  -webkit-backdrop-filter:blur(16px) saturate(160%);
  backdrop-filter:blur(16px) saturate(160%);
  transition:transform .15s,background .15s;
}
.theme-toggle:hover{transform:translateY(-1px);background:var(--glass-2)}
.egg .theme-toggle{display:none}
.hint{
  margin:0 0 12px;padding:9px 12px;border-radius:11px;
  background:var(--warn-bg);border:1px solid var(--warn-border);
  color:var(--warn-ink);font-size:12.5px;line-height:1.7;
}
code,.hint code,.admin code{
  background:var(--code-bg);color:var(--code-ink);
  padding:1px 6px;border-radius:6px;font-size:12px;
}
.egg code{background:rgba(255,255,255,.11);color:#cfe0ff}
`;

const uiThemeScript = '<script>' + "(function(){\nvar d=document.documentElement,k='ui-theme';\nvar m=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)');\nvar saved=null;try{saved=localStorage.getItem(k)}catch(e){}\nvar cur=saved||(m&&m.matches?'dark':'light');\nd.setAttribute('data-theme',cur);\nfunction sync(){var b=document.getElementById('themeToggle');if(!b)return;var dark=d.getAttribute('data-theme')==='dark';b.textContent=dark?'明':'暗';b.title=dark?'切换浅色':'切换深色';}\nfunction set(v){d.setAttribute('data-theme',v);sync();}\nif(m&&m.addEventListener){m.addEventListener('change',function(e){var s=null;try{s=localStorage.getItem(k)}catch(x){}if(!s)set(e.matches?'dark':'light');});}\ndocument.addEventListener('DOMContentLoaded',function(){\n  var b=document.createElement('button');b.type='button';b.id='themeToggle';b.className='theme-toggle';b.setAttribute('aria-label','切换深浅色');\n  document.body.appendChild(b);sync();\n  b.addEventListener('click',function(){var v=d.getAttribute('data-theme')==='dark'?'light':'dark';try{localStorage.setItem(k,v)}catch(e){}set(v);});\n});\n})();" + '</script>';

function uiHead(title) {
  return '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
  '<title>' + title + '</title><style>' + uiCss + '</style>' + uiThemeScript;
}

const indexHtml = `<!DOCTYPE html>
<html><head>${uiHead("作业提交")}</head>
<body class="app front">
<div class="aurora" aria-hidden="true"><span></span><span></span></div>
<main class="shell">
<header class="hero">
<div class="brand"><span class="dot"></span> 作业提交系统</div>
<h1>📤 作业提交</h1>
<p class="lede">填写小组与学号，选择文件即可完成提交。</p>
</header>
<div id="closedTip" class="glass notice notice-warn" style="display:none">⏰ <b>提交已截止</b>。如有老师给的临时凭证，在下方验证后可补交一次。</div>
<section class="glass card"><div id="box"></div></section>
<section class="glass card">
<div class="section-head"><h2>📋 提交情况</h2><span class="pill">实时</span></div>
<div id="status"></div>
</section>
<footer class="foot">简洁提交 · 安全存储</footer>
<footer class="foot">该系统全量开源：https://github.com/WhisperSea-LS/homework-submit</footer>
</main>
<script>
let CFG = null;
let STORAGE = null;
let deadlinePassed = false;
let GRANT_OK = "";
const typeLabels = {video:"视频",audio:"音频",image:"图片",ppt:"PPT",doc:"其他文档"};
const acceptMap = {
  video:"video/*", audio:"audio/*", image:"image/*",
  ppt:".ppt,.pptx", doc:".pdf,.doc,.docx,.zip,.rar"
};
async function init() {
  try {
    const [cfgRes, storRes, dlRes] = await Promise.all([
      fetch('/api/config', {cache:'no-store'}),
                                                       fetch('/api/storage-public', {cache:'no-store'}),
                                                       fetch('/api/deadline', {cache:'no-store'})
    ]);
    CFG = await cfgRes.json();
    STORAGE = await storRes.json();
    const dl = await dlRes.json();
    deadlinePassed = dl.passed;
  } catch(e) {
    document.getElementById('box').innerHTML = '<p class="msg err">加载配置失败，请刷新重试</p>';
    return;
  }
  render();
  loadStatus();
}
function renderGrantGate(box) {
  box.innerHTML =
    '<h3>🔑 临时提交凭证</h3>' +
    '<p class="lede" style="font-size:13px;margin:0 0 14px">提交已截止。如果老师给了临时凭证，输入并验证后即可补交一次；凭证在提交成功后自动作废。</p>' +
    '<p><input id="grantInput" placeholder="粘贴临时凭证" autocomplete="off" spellcheck="false" style="width:100%"></p>' +
    '<button type="button" class="btn btn-primary btn-block" onclick="verifyGrant()">验证凭证</button>' +
    '<p id="grantMsg" class="msg"></p>';
}
async function verifyGrant() {
  var el = document.getElementById('grantInput');
  var msg = document.getElementById('grantMsg');
  var v = el ? el.value.trim() : '';
  if (!v) { msg.textContent = '请输入凭证'; return; }
  msg.textContent = '验证中…';
  try {
    var r = await fetch('/api/grant-verify', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ grant: v })
    });
    if (!r.ok) { msg.textContent = await r.text(); return; }
    GRANT_OK = v;
    render();
  } catch(e) { msg.textContent = '网络错误，请重试'; }
}
function render() {
  const box = document.getElementById('box');
  box.style.display = '';
  document.getElementById('closedTip').style.display = 'none';
  if (deadlinePassed && !GRANT_OK) {
    document.getElementById('closedTip').style.display = 'block';
    renderGrantGate(box);
    return;
  }
  if (!CFG.submissionOpen) {
    box.innerHTML = '<p class="msg err">当前已关闭提交</p>';
    return;
  }
  let h = '';
  if (GRANT_OK) {
    h += '<div class="glass notice" style="padding:10px 14px;margin:0 0 14px;font-size:13px;border-color:rgba(21,154,104,.35);color:#128a5d">🔑 临时凭证已验证，本次提交成功后自动作废。</div>';
  }
  h += '<form id="f">';
  if (CFG.groupMode) {
    h += '<p>小组名：<input name="group" required placeholder="如：第1组"></p>';
    h += '<p>学号（最多 ' + CFG.groupSize + ' 个）：</p>';
    if (CFG.testMode) h += '<p class="hint">🧪 测试模式已开启：学号可填 <code>-1</code>（需单独提交）</p>';
    for (let i = 0; i < CFG.groupSize; i++) {
      h += '<input name="sid" placeholder="学号' + (i+1) + '" ' + (i===0?'required':'') + ' class="sid-input">';
    }
  } else {
    h += '<p>学号：<input name="sid" required placeholder="请输入学号"></p>';
    if (CFG.testMode) h += '<p class="hint">🧪 测试模式已开启：学号可填 <code>-1</code></p>';
    h += '<input type="hidden" name="group" value="personal">';
  }
  h += '<p>提交类型：<select name="submitType">';
  CFG.submitTypes.forEach(function(t) {
    h += '<option value="' + t + '">' + (typeLabels[t]||t) + '</option>';
  });
  h += '</select></p>';
  h += '<p>文件：<input type="file" id="fileInput" required></p>';
  h += '<button type="button" class="btn btn-primary btn-block" onclick="doUpload()">提交</button>';
  h += '</form>';
  h += '<div id="progress" class="progress"></div>';
  h += '<p id="msg" class="msg"></p>';
  box.innerHTML = h;
  var sel = document.querySelector('select[name="submitType"]');
  var fi = document.getElementById('fileInput');
  if (sel && fi) {
    fi.accept = acceptMap[sel.value] || "";
    sel.addEventListener('change', function() { fi.accept = acceptMap[sel.value] || ""; });
  }
}
function isValidSid(sid) {
  var t = sid.trim();
  if (CFG.testMode && t === '-1') return true;
  if (!/^\\d{1,10}$/.test(t)) return false;
  var n = Number(t);
  if (n < 1 || n > 9999999999) return false;
  var allowed = (CFG.allowedSids && CFG.allowedSids.length)
  ? CFG.allowedSids.map(String)
  : Array.from({length:48}, function(_, i){ return String(i + 1); });
  return allowed.indexOf(String(n)) >= 0;
}
function sidRuleText() {
  if (CFG.testMode) return '可填名单内学号，或测试学号 -1';
  return '需为应提交名单内的学号（默认 1~48）';
}
function setMsg(s) { var el = document.getElementById('msg'); if (el) el.textContent = s; }
function setProgress(s) { var el = document.getElementById('progress'); if (el) el.innerHTML = s; }
function convertImageToPNG(file) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const reader = new FileReader();
    reader.onload = (e) => {
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        ctx.fillStyle = '#FFFFFF';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0);
        canvas.toBlob((blob) => {
          if (blob) {
            const newName = file.name.replace(/\.[^.]+$/, '') + '.png';
            resolve(new File([blob], newName, { type: 'image/png' }));
          } else {
            reject(new Error('Canvas 转 PNG 失败'));
          }
        }, 'image/png', 0.92);
      };
      img.onerror = () => reject(new Error('图片加载失败'));
      img.src = e.target.result;
    };
    reader.onerror = () => reject(new Error('文件读取失败'));
    reader.readAsDataURL(file);
  });
}
async function loadStatus() {
  try {
    var res = await fetch('/api/status', {cache:'no-store'});
    var data = await res.json();
    var div = document.getElementById('status');
    var mL = data.missingLabels || data.missing;
    var sL = data.submittedLabels || data.submitted;
    var h = '<p>✅ 已交：' + data.submitted.length + ' 人</p>';
    h += '<p>❌ 未交：' + data.missing.length + ' 人</p>';
    if (data.groups.length) {
      h += '<details open><summary>已提交分组</summary><ul>';
      data.groups.forEach(function(g) {
        h += '<li><b>' + g.name + '</b>：' + (g.memberLabels || g.members).join(', ') + '</li>';
      });
      h += '</ul></details>';
    }
    if (data.missing.length) {
      h += '<details><summary>未交名单</summary>' + mL.join(', ') + '</details>';
    }
    div.innerHTML = h;
  } catch(e) {}
}
async function doUpload() {
  var form = document.getElementById('f');
  if (!form) return setMsg('表单未加载');
  var group = form.group.value.trim();
  var sids = Array.from(form.querySelectorAll('input[name="sid"]')).map(function(i){ return i.value.trim(); }).filter(function(v){ return v; });
  var submitType = form.submitType ? form.submitType.value : 'unknown';
  var fileInput = document.getElementById('fileInput');
  if (!fileInput) return setMsg('文件选择器未找到');
  var file = fileInput.files[0];
  if (CFG.groupMode && group.toLowerCase() === 'personal') {
    location.href = '/egg?from=' + encodeURIComponent(group);
    return;
  }
  if (CFG.groupMode) { if (!group) return setMsg('请填写小组名'); if (group.length > 50) return setMsg('小组名不能超过50个字符'); }
  if (sids.length === 0) return setMsg('至少填一个学号');
  var eggSid = sids.find(function(s){ return s === '-1'; });
  if (eggSid && !CFG.testMode) { location.href = '/egg?from=' + encodeURIComponent(eggSid); return; }
  if (eggSid && sids.length > 1) return setMsg('测试学号 -1 需单独提交');
  if (CFG.groupMode && sids.length > CFG.groupSize) return setMsg('最多填 ' + CFG.groupSize + ' 个学号');
  for (var i = 0; i < sids.length; i++) {
    if (!isValidSid(sids[i])) return setMsg('学号「' + sids[i] + '」不在允许范围内，' + sidRuleText());
  }
  if (new Set(sids).size !== sids.length) return setMsg('学号不能重复');
  if (!file) return setMsg('请选择文件');
  if (file.size > 1024 * 1024 * 1024) return setMsg('文件不能超过 1GB');

  if (file.type.startsWith('image/')) {
    setProgress('① 正在转换为 PNG 格式...');
    try {
      file = await convertImageToPNG(file);
      file = new File([file], sids.join('-') + '.png', { type: 'image/png' });
    } catch (e) {
      return setMsg('PNG 转换失败: ' + e.message);
    }
  }

  setProgress('① 获取上传凭证...');
  var meta;
  try {
    var r1 = await fetch('/api/presign', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ group: group, sids: sids, filename: file.name, type: file.type, submitType: submitType, grant: GRANT_OK })
    });
    if (r1.status === 400) {
      var err = null;
      try { err = await r1.json(); } catch (e2) {}
      if (err && err.egg) { location.href = '/egg?from=' + encodeURIComponent(err.from || group); return; }
    }
    if (!r1.ok) {
      var why = await r1.text();
      // 页面打开后管理员才点「立即截止」：就地切到临时凭证入口
      if (why.indexOf('提交已截止') >= 0) { deadlinePassed = true; render(); return; }
      return setMsg(why);
    }
    meta = await r1.json();
  } catch(e) { return setMsg('网络错误，请重试'); }
  try {
    if (STORAGE.backend === 'webdav' && STORAGE.webdav) {
      await uploadWebDAV(meta.token, file);
    } else {
      await uploadViaProxy(meta.key, meta.token, file);
    }
    if (GRANT_OK) {
      GRANT_OK = '';
      document.getElementById('box').innerHTML = '<p class="msg" style="color:#128a5d">✅ 提交成功，临时凭证已作废。如需再次补交，请联系老师获取新凭证。</p>';
      loadStatus();
    } else {
      setMsg('✅ 提交成功！');
      loadStatus();
    }
  } catch(e) { setMsg('上传失败: ' + e.message); }
}
async function recordUpload(token, file) {
  var r2 = await fetch('/api/upload', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ token: token, originalName: file.name, size: file.size })
  });
  if (!r2.ok) throw new Error('提交记录失败: ' + (await r2.text()));
}
function uploadViaProxy(key, token, file) {
  return new Promise(function(resolve, reject) {
    var fd = new FormData();
    fd.append('token', token);
    fd.append('file', file);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload-proxy');
    xhr.upload.onprogress = function(e) { if (e.lengthComputable) setProgress('② 上传中 ' + Math.round(e.loaded/e.total*100) + '%'); };
    xhr.onload = async function() {
      if (xhr.status === 200 || xhr.status === 204) {
        setProgress('③ 记录提交信息...');
        try { await recordUpload(token, file); resolve(); }
        catch(e) { reject(e); }
      } else { reject(new Error('代理上传返回 ' + xhr.status + ': ' + xhr.responseText)); }
    };
    xhr.onerror = function() { reject(new Error('网络错误')); };
    xhr.send(fd);
  });
}
async function uploadWebDAV(token, file) {
  var proxyUrl = '/api/webdav-upload?token=' + encodeURIComponent(token);
  setProgress('② WebDAV 上传中... 0%');
  await new Promise(function(resolve, reject) {
    var xhr = new XMLHttpRequest();
    xhr.open('PUT', proxyUrl);
    xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
    xhr.upload.onprogress = function(e) { if (e.lengthComputable) setProgress('② WebDAV 上传中... ' + Math.round(e.loaded / file.size * 100) + '%'); };
    xhr.onload = async function() {
      if (xhr.status >= 200 && xhr.status < 300) {
        setProgress('③ 记录提交信息...');
        try { await recordUpload(token, file); resolve(); }
        catch(e) { reject(e); }
      } else { reject(new Error('代理上传失败: HTTP ' + xhr.status)); }
    };
    xhr.onerror = function() { reject(new Error('网络错误')); };
    xhr.send(file);
  });
  setProgress('');
}
init();
</script>
</main></body></html>`;

function eggHtml(raw) {
  const shown = escapeHtml(String(raw || "personal").slice(0, 50));
  const sidEgg = String(raw || "").trim() === "-1";
  const q1 = sidEgg ? "① 你知道 -1 在系统里代表什么吗？" : "① 你知道 personal 是什么意思吗？";
  const q2 = "② 为什么要在「" + (sidEgg ? "学号" : "小组名") + "」里填它？";
  const note = sidEgg
  ? "小科普：<code>-1</code> 是预留的测试学号，只有后台「测试模式」开启时才会被接受；没开启时填它就会跳到这里。你填的原文只显示在这个页面上，不会发给服务器。"
  : "小科普：关掉小组制后，每个人单独交的作业会统一记在 <code>grp:personal</code> 下。如果小组模式也允许叫 personal，两种提交就会挤进同一个分组里，成员和文件会串在一起——所以它被拦下了。你填的原文只显示在这个页面上，不会发给服务器。";
  const lede1 = sidEgg
  ? "这个学号被系统保留了，测试模式没开时不能提交。"
  : "这个词被系统保留了，小组模式下不能当组名用。";
  const lede2 = sidEgg ? "先回答三个问题，再回去换个学号 👇" : "先回答三个问题，再回去换个名字 👇";
  const backText = sidEgg ? "← 回去老实填学号" : "← 回去老实填小组名";
  const whyHint = sidEgg ? "比如：手滑 / 好奇 / 觉得是个隐藏学号……" : "比如：手滑 / 好奇 / 觉得听起来像个组名……";
  const pageTitle = sidEgg ? "🕵️ -1 彩蛋" : "🕵️ personal 彩蛋";
  const q3Opts = sidEgg
  ? '<div class="opts" data-q="q3">' +
  '<button class="btn opt" data-v="翻过源码了">翻过源码了 😏</button>' +
  '<button class="btn opt" data-v="纯手滑">纯手滑</button>' +
  '<button class="btn opt" data-v="我猜它是测试学号">我猜它是测试学号</button>' +
  '<button class="btn opt" data-v="只是来试探彩蛋">只是来试探彩蛋</button></div>'
  : '<div class="opts" data-q="q3">' +
  '<button class="btn opt" data-v="翻过源码了">翻过源码了 😏</button>' +
  '<button class="btn opt" data-v="纯手滑">纯手滑</button>' +
  '<button class="btn opt" data-v="我猜它是保留字">我猜它是保留字</button>' +
  '<button class="btn opt" data-v="只是来试探彩蛋">只是来试探彩蛋</button></div>';
  const verdicts = sidEgg ? [
    "结论：好眼力，-1 确实写在代码里，而且只有后台打开测试模式才会放行。不过作业还是要按名单内的学号交 😄",
    "结论：猜对了，-1 是预留的测试学号。真想交它，得让管理员打开测试模式 👇",
    "结论：手滑无罪，回去换个名单内的学号就行 🙌",
    "结论：不管怎么来的，-1 这个彩蛋你算是找到了 🎉"
  ] : [
    "结论：好眼力，grp:personal 确实写在代码里。不过作业还是要按小组名交 😄",
    "结论：猜对了，就是保留字。奖励你一个返回按钮 👇",
    "结论：手滑无罪，回去改个组名就行 🙌",
    "结论：不管怎么来的，这个彩蛋你算是找到了 🎉"
  ];
  const verdictJs = JSON.stringify(verdicts);
  const q1Opts = sidEgg
  ? '<div class="opts" data-q="q1">' +
  '<button class="btn opt" data-v="知道，是测试学号">知道，是测试学号</button>' +
  '<button class="btn opt" data-v="大概猜得到">大概猜得到</button>' +
  '<button class="btn opt" data-v="看提示说的">看提示说的</button>' +
  '<button class="btn opt" data-v="完全不知道">完全不知道</button></div>'
  : '<div class="opts" data-q="q1">' +
  '<button class="btn opt" data-v="知道，就是「个人的」">知道，就是「个人的」</button>' +
  '<button class="btn opt" data-v="大概猜得到">大概猜得到</button>' +
  '<button class="btn opt" data-v="刚查的">刚查的</button>' +
  '<button class="btn opt" data-v="完全不知道">完全不知道</button></div>';
  return String.raw`<!DOCTYPE html>
  <html><head>${uiHead(pageTitle)}</head>
  <body class="app egg">
  <div class="aurora" aria-hidden="true"><span></span><span></span></div>
  <main class="shell">
  <header class="hero">
  <div class="brand"><span class="dot"></span> 彩蛋</div>
  <h1>🕵️ 你填了「<span>${shown}</span>」？</h1>
  <p class="lede">${lede1}</p>
  <p class="lede">${lede2}</p>
  </header>
  <section class="glass card"><h2>${q1}</h2>
  ${q1Opts}</section>
  <section class="glass card"><h2>${q2}</h2>
  <textarea id="why" placeholder="${whyHint}"></textarea></section>
  <section class="glass card"><h2>③ 是猜到我的代码怎么写的了吗？</h2>
  ${q3Opts}</section>
  <button class="btn btn-primary btn-block" id="go">提交口供（不会上传，纯本地娱乐）</button>
  <div id="verdict" class="glass"></div>
  <a class="back" href="/">${backText}</a>
  <p class="note">${note}</p>
  </div>
  <script>
  var V = ${verdictJs};
  var answers = {q1:'', q3:''};
  document.querySelectorAll('.opts').forEach(function(box){
    var q = box.dataset.q;
    box.querySelectorAll('.opt').forEach(function(btn){
      btn.addEventListener('click', function(){
        box.querySelectorAll('.opt').forEach(function(b){ b.classList.remove('on'); });
        btn.classList.add('on');
        answers[q] = btn.dataset.v;
      });
    });
  });
  document.getElementById('go').addEventListener('click', function(){
    var why = document.getElementById('why').value.trim() || '（没写，沉默也是一种回答）';
    var q1 = answers.q1 || '（没选）';
    var q3 = answers.q3 || '（没选）';
    var lines = ['📝 口供记录', '① ' + q1, '② ' + why, '③ ' + q3, ''];
    if (q3.indexOf('源码') >= 0) lines.push(V[0]);
    else if (q3.indexOf('保留字') >= 0 || q3.indexOf('测试学号') >= 0) lines.push(V[1]);
    else if (q3.indexOf('手滑') >= 0) lines.push(V[2]);
    else lines.push(V[3]);
    lines.push('', '放心，以上全部只在你自己的浏览器里，没发到服务器。');
    var v = document.getElementById('verdict');
    v.textContent = lines.join(String.fromCharCode(10));
    v.style.display = 'block';
    v.scrollIntoView({behavior:'smooth', block:'nearest'});
  });
  </script>
  </main></body></html>`;
}

export default {
  async fetch(req, env, ctx) {
    try { return await router(req, env, ctx); }
    catch (e) {
      console.error(e);
      return new Response("服务器内部错误", {
        status: 500,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }
  }
};

async function router(req, env, ctx) {
  var url = new URL(req.url);

  if (url.pathname === "/") {
    return new Response(indexHtml, {
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
    });
  }

  if (url.pathname === "/egg") {
    return new Response(eggHtml(url.searchParams.get("from")), {
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
    });
  }

  if (url.pathname === "/api/config") {
    const cfg = await getConfig(env);
    return Response.json(Object.assign({}, cfg, {
      allowedSids: getExpectedSids(cfg),
                                       testMode: !!cfg.testMode
    }), { headers: { "Cache-Control": "no-store" } });
  }

  if (url.pathname === "/api/storage-public") {
    var cfg = await getStorageConfig(env);
    return Response.json({
      backend: cfg.backend,
      webdav: cfg.backend === "webdav" ? { configured: !!cfg.webdav.baseUrl } : null
    }, { headers: { "Cache-Control": "no-store" } });
  }

  if (url.pathname === "/api/deadline") return handleGetDeadline(req, env);
  if (url.pathname === "/api/grant-verify") return handleGrantVerify(req, env);
  if (url.pathname === "/api/status") return handleStatus(req, env);
  if (url.pathname === "/api/presign") return handlePresign(req, env);
  if (url.pathname === "/api/upload") return handleUpload(req, env);
  if (url.pathname === "/api/upload-proxy") return handleUploadProxy(req, env);
  if (url.pathname === "/api/webdav-upload") return handleWebDAVProxy(req, env);

  if (url.pathname === "/admin") return handleAdmin(req, env);
  if (url.pathname === "/admin/config") return handleAdminConfig(req, env);
  if (url.pathname === "/admin/names") return handleAdminNames(req, env);
  if (url.pathname === "/admin/storage") return handleAdminStorage(req, env);
  if (url.pathname === "/admin/test-storage") return handleTestStorage(req, env);
  if (url.pathname === "/admin/clear-submissions") return handleClearSubmissions(req, env);
  if (url.pathname === "/admin/set-deadline") return handleSetDeadline(req, env);
  if (url.pathname === "/admin/grant-add") return handleGrantAdd(req, env);
  if (url.pathname === "/admin/grant-delete") return handleGrantDelete(req, env);
  if (url.pathname === "/admin/edit-members") return handleEditMembers(req, env);
  if (url.pathname.startsWith("/admin/delete/")) return handleDeleteGroup(req, env);
  if (url.pathname.startsWith("/admin/delete-file/")) return handleDeleteFile(req, env);
  if (url.pathname.startsWith("/admin/mark-downloaded/")) return handleMarkDownloaded(req, env);
  if (url.pathname.startsWith("/admin/download/")) return handleDownload(req, env);
  if (url.pathname === "/admin/download-zip") return handleDownloadZip(req, env, ctx);
  if (url.pathname.startsWith("/ac6694e52bf4e8a7ed70febe7f591b4e.txt")) return new Response("2da07700dc16bf37265a588b796fb64c0f110f94", { status: 200 });

  return new Response("Not Found", { status: 404 });
}

async function handleUploadProxy(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

  try {
    const form = await req.formData();
    const file = form.get("file");
    const claims = await readPayload(env, form.get("token"));
    var closed = await assertSubmissionOpen(env, !!(claims && claims.grant));
    if (closed) return new Response(closed, { status: 403 });
    if (!file || !claims || claims.scope !== "upload" || !claims.key) {
      return new Response("上传凭证无效或已过期", { status: 403 });
    }

    const store = await getStorageConfig(env);
    if (store.backend !== "b2" && store.backend !== "s3") {
      return new Response("存储未配置", { status: 500 });
    }
    const client = storageClient(store);
    const upstream = await client.putObject(claims.key, file.stream(), file.type || "application/octet-stream");

    if (!upstream.ok) {
      return new Response("对象存储上传失败: " + upstream.status, { status: 502 });
    }
    return new Response("OK", { status: 200 });
  } catch (e) {
    console.error(e);
    return new Response("代理上传异常", { status: 500 });
  }
}

async function handleGetDeadline(req, env) {
  var deadline = await getDeadline(env);
  return Response.json({
    deadline: deadline,
    passed: deadline !== null ? Date.now() >= deadline : false,
                       now: Date.now()
  }, { headers: { "Cache-Control": "no-store" } });
}

// 只校验、不核销：真正的核销发生在 /api/upload 的 DO 串行区里
async function handleGrantVerify(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  var cfg = await getConfig(env);
  if (!cfg.submissionOpen) return new Response("当前已关闭提交", { status: 403 });
  var body;
  try { body = await req.json(); } catch (_) { return new Response("请求格式错误", { status: 400 }); }
  var id = normalizeGrant(body && body.grant);
  if (!id) return new Response("请输入凭证", { status: 400 });
  var g = await getGrant(env, id);
  if (!g || g.used) return new Response("临时凭证无效或已被使用", { status: 403 });
  return Response.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });
}

async function handleGrantAdd(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  var fd = await req.formData();
  if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
  var note = String(fd.get("note") || "").trim().slice(0, 60);
  var id = crypto.randomUUID().toLowerCase();
  await env.GROUP_KV.put("grant:" + id, JSON.stringify({
    created: Date.now(), note: note, used: false
  }));
  return Response.redirect(new URL(req.url).origin + "/admin#grants", 302);
}

async function handleGrantDelete(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  var fd = await req.formData();
  if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
  var id = normalizeGrant(fd.get("id"));
  if (id) await env.GROUP_KV.delete("grant:" + id);
  return Response.redirect(new URL(req.url).origin + "/admin#grants", 302);
}

async function handleStatus(req, env) {
  var cfg = await getConfig(env);
  var nmap = await getNameMap(env);
  var keys = await listGroupKeys(env);
  var groups = [];
  var allSids = new Set();
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var g = JSON.parse(await env.GROUP_KV.get(k) || "{}");
    var name = k.slice(4);
    if (!cfg.groupMode && name === "personal") {
      for (var j = 0; j < (g.members || []).length; j++) {
        var one = g.members[j];
        groups.push({ name: labelOf(nmap, one), members: [one], memberLabels: [labelOf(nmap, one)] });
        allSids.add(one);
      }
    } else {
      groups.push({
        name: name,
        members: g.members || [],
        memberLabels: (g.members || []).map(function (s) { return labelOf(nmap, s); })
      });
      for (var j = 0; j < (g.members || []).length; j++) allSids.add(g.members[j]);
    }
  }
  var missing = getExpectedSids(cfg).filter(function (sid) { return !allSids.has(sid); });
  return Response.json({
    groups: groups,
    submitted: Array.from(allSids),
                       submittedLabels: Array.from(allSids).map(function (s) { return labelOf(nmap, s); }),
                       missing: missing,
                       missingLabels: missing.map(function (s) { return labelOf(nmap, s); })
  }, { headers: { "Cache-Control": "no-store" } });
}

async function handlePresign(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  var body = await req.json();
  var cfg = await getConfig(env);
  var store = await getStorageConfig(env);

  // 凭证只在「已截止」时生效；未截止的正常提交不会消耗凭证
  var deadline = await getDeadline(env);
  var deadlinePassed = deadline !== null && Date.now() >= deadline;
  var grant = deadlinePassed ? normalizeGrant(body && body.grant) : "";
  var grantRecord = grant ? await getGrant(env, grant) : null;
  if (grant && (!grantRecord || grantRecord.used)) {
    return new Response("临时凭证无效或已被使用", { status: 403 });
  }
  var closed = await assertSubmissionOpen(env, !!grantRecord);
  if (closed) return new Response(closed, { status: 403 });

  var group = cfg.groupMode ? String(body.group || "").trim() : "personal";
  if (cfg.groupMode && group.toLowerCase() === "personal") {
    return Response.json({ egg: true, from: group, message: "personal 是保留组名" }, { status: 400 });
  }
  if (cfg.groupMode && !isValidGroupName(group)) return new Response("小组名格式不合法", { status: 400 });

  var sids = body.sids;
  if (!Array.isArray(sids) || sids.length === 0) return new Response("至少需要一个学号", { status: 400 });
  if (cfg.groupMode && sids.length > cfg.groupSize) return new Response("学号数量超过限制", { status: 400 });
  if (!cfg.groupMode && sids.length > 1) return new Response("个人模式只能提交一个学号", { status: 400 });
  const allowed = new Set(getExpectedSids(cfg));
  var validSids = [];
  for (var i = 0; i < sids.length; i++) {
    var sid = String(sids[i]).trim();
    if (sid === "-1") {
      if (!cfg.testMode) {
        return Response.json({ egg: true, from: "-1", message: "-1 需要测试模式" }, { status: 400 });
      }
      if (sids.length > 1) return new Response("测试学号 -1 需单独提交", { status: 400 });
      validSids.push(sid);
      continue;
    }
    if (!isValidStudentId(sid)) return new Response("学号「" + sid + "」格式不正确", { status: 400 });
    if (!allowed.has(String(Number(sid)))) {
      return new Response("学号「" + sid + "」不在允许范围内", { status: 400 });
    }
    validSids.push(sid);
  }
  if (new Set(validSids).size !== validSids.length) return new Response("学号不能重复", { status: 400 });

  var submitType = String(body.submitType || "");
  if (!Array.isArray(cfg.submitTypes) || !cfg.submitTypes.includes(submitType)) {
    return new Response("提交类型不合法", { status: 400 });
  }

  var gRaw = await env.GROUP_KV.get("grp:" + group);
  if (gRaw) {
    var g = JSON.parse(gRaw);
    for (var i = 0; i < validSids.length; i++) {
      if ((g.members || []).includes(validSids[i])) {
        return new Response("学号" + validSids[i] + "已在该组提交过", { status: 409 });
      }
    }
  }
  for (var i = 0; i < validSids.length; i++) {
    var ex = await env.GROUP_KV.get("sid:" + validSids[i]);
    if (ex && ex !== group) return new Response("学号" + validSids[i] + "已在「" + ex + "」组", { status: 409 });
  }

  var key = buildObjectKey(group, validSids, body.filename);
  var claims = {
    scope: "upload",
    group: group,
    sids: validSids,
    key: key,
    submitType: submitType,
    grant: grant,
    nonce: crypto.randomUUID(),
    exp: Date.now() + 2 * 3600 * 1000
  };
  var token = await signPayload(env, claims);
  return Response.json({ backend: store.backend, key: key, token: token });
}

async function handleUpload(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  var body = await req.json();
  var claims = await readPayload(env, body.token);
  if (!claims || claims.scope !== "upload" || !claims.nonce || !claims.key || !Array.isArray(claims.sids)) {
    return new Response("上传凭证无效或已过期", { status: 403 });
  }
  var closed = await assertSubmissionOpen(env, !!claims.grant);
  if (closed) return new Response(closed, { status: 403 });
  var originalName = String(body.originalName || claims.key)
  .slice(0, 200)
  .replace(/[\/\\:*?"<>|\r\n]/g, "_");

  var id = env.GROUP_DO.idFromName("submissions");
  var stub = env.GROUP_DO.get(id);
  var resp = await stub.fetch("https://do/commit", {
    method: "POST",
    body: JSON.stringify({
      action: "commit",
      group: claims.group,
      payload: {
        sids: claims.sids,
        claims: claims,
        grant: normalizeGrant(claims.grant),
        file: {
          key: claims.key,
          originalName: originalName,
          size: Number(body.size) || 0,
                         time: Date.now(),
                         downloaded: false,
                         submitType: claims.submitType || "unknown"
        }
      }
    })
  });
  var result = await resp.json();
  if (!result.ok) return new Response(result.reason || "提交失败", { status: 409 });
  return new Response("OK");
}

async function handleWebDAVProxy(req, env) {
  try {
    if (req.method !== "PUT") return new Response("Method Not Allowed", { status: 405 });
    const url = new URL(req.url);
    const claims = await readPayload(env, url.searchParams.get("token"));
    var closed = await assertSubmissionOpen(env, !!(claims && claims.grant));
    if (closed) return new Response(closed, { status: 403 });
    if (!claims || claims.scope !== "upload" || !claims.key) {
      return new Response("上传凭证无效或已过期", { status: 403 });
    }
    const store = await getStorageConfig(env);
    if (store.backend !== "webdav") return new Response("WebDAV not configured", { status: 400 });
    const dav = store.webdav;
    const base = String(dav.baseUrl || "").replace(/\/+$/, "");
    const cleanKey = encodeStorageKey(claims.key);
    const targetUrl = base + "/" + cleanKey;
    const auth = "Basic " + btoa(dav.username + ":" + dav.password);
    const dir = cleanKey.split("/").slice(0, -1).join("/");
    if (dir) {
      await fetch(base + "/" + dir, { method: "MKCOL", headers: { Authorization: auth } });
    }
    const upstream = await fetch(targetUrl, {
      method: "PUT",
      headers: {
        Authorization: auth,
        "Content-Type": req.headers.get("Content-Type") || "application/octet-stream"
      },
      body: req.body,
      duplex: "half"
    });
    if (!upstream.ok) return new Response("WebDAV upstream " + upstream.status, { status: 502 });
    return new Response(null, { status: 204 });
  } catch (e) {
    console.error(e);
    return new Response("Proxy error", { status: 500 });
  }
}

async function handleAdmin(req, env) {
  if (!await authOk(req, env)) return basicChallenge();
  var at = await makeAdminToken(env);
  var cfg = await getConfig(env);
  var store = await getStorageConfig(env);
  var deadline = await getDeadline(env);
  var now = Date.now();
  var keys = await listGroupKeys(env);
  var nmap = await getNameMap(env);
  var grants = await listGrants(env);
  var totalSize = 0, undownloadedSize = 0;
  var groupDataList = [];
  var allSids = new Set();
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var g = JSON.parse(await env.GROUP_KV.get(k) || "{}");
    var gn = k.slice(4);
    for (var j = 0; j < (g.members || []).length; j++) allSids.add(g.members[j]);
    for (var j = 0; j < (g.files || []).length; j++) {
      totalSize += (g.files[j].size || 0);
      if (!g.files[j].downloaded) undownloadedSize += (g.files[j].size || 0);
    }
    groupDataList.push({ name: gn, data: g });
  }
  function fmt(b) {
    return b >= 1024 * 1024 * 1024 ? (b/1024/1024/1024).toFixed(2) + " GB" : (b/1024/1024).toFixed(1) + " MB";
  }
  var missing = getExpectedSids(cfg).filter(function (s) { return !allSids.has(s); });

  var deadlineHtml = "";
  if (deadline) {
    var d = new Date(deadline);
    var passed = now >= deadline;
    var remain = deadline - now;
    var remainStr = passed ? "已截止" :
    "剩 " + Math.floor(remain/86400000) + "天 " +
    Math.floor(remain%86400000/3600000) + "小时 " +
    Math.floor(remain%3600000/60000) + "分";
    var localStr = new Date(deadline - d.getTimezoneOffset()*60000).toISOString().slice(0,16);
    deadlineHtml +=
    '<div style="border:1px solid #ff9900;background:#fffaf0;padding:12px 16px;border-radius:8px;margin:12px 0">' +
    '<b>⏰ 提交截止时间：</b> ' + d.toLocaleString() +
    ' <span style="color:' + (passed?'#c00':'#28a745') + '">(' + remainStr + ')</span>' +
    '<form method="POST" action="/admin/set-deadline" style="margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
    '<input type="hidden" name="token" value="' + at + '">' +
    '<input type="hidden" name="action" value="set">' +
    '<input type="datetime-local" name="dt" value="' + localStr + '" style="padding:4px 8px">' +
    '<input type="hidden" name="at_ts" id="ts">' +
    '<button type="submit" onclick="document.getElementById(\'ts\').value=Math.floor(new Date(document.querySelector(\'[name=dt]\').value).getTime())" class="btn btn-primary btn-xs">💾 更新截止时间</button>' +
    '</form>' +
    '<div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">' +
    '<form method="POST" action="/admin/set-deadline" onsubmit="return confirm(\'清除截止时间？提交将重新开放\')">' +
    '<input type="hidden" name="token" value="' + at + '"><input type="hidden" name="action" value="clear">' +
    '<button type="submit" class="btn btn-danger-ghost btn-xs">🗑 清除</button></form>' +
    '<form method="POST" action="/admin/set-deadline" onsubmit="return confirm(\'立即截止当前提交？\')">' +
    '<input type="hidden" name="token" value="' + at + '"><input type="hidden" name="action" value="set"><input type="hidden" name="at" value="now">' +
    '<button type="submit" class="btn btn-danger btn-xs">⛔ 立即截止</button></form>' +
    '</div></div>';
  } else {
    deadlineHtml +=
    '<div style="border:1px dashed #ccc;padding:12px 16px;border-radius:8px;margin:12px 0;color:#666">' +
    '⏰ 当前<b>未设置截止时间</b>（提交持续开放）' +
    '<form method="POST" action="/admin/set-deadline" style="margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
    '<input type="hidden" name="token" value="' + at + '"><input type="hidden" name="action" value="set">' +
    '<input type="datetime-local" name="dt" style="padding:4px 8px">' +
    '<input type="hidden" name="at_ts" id="ts2">' +
    '<button type="submit" onclick="document.getElementById(\'ts2\').value=Math.floor(new Date(document.querySelector(\'[name=dt]\').value).getTime())" class="btn btn-primary btn-xs">➕ 设置截止时间</button>' +
    '</form></div>';
  }

  var html = "";
  html += '<!DOCTYPE html><html><head>' + uiHead('作业后台') + '</head>';
  html += '<body class="app admin"><div class="aurora" aria-hidden="true"><span></span><span></span></div><main class="shell shell-wide">';
  html += '<header class="hero"><div class="brand"><span class="dot"></span> 管理后台</div><h1>📁 作业后台</h1>';
  html += '<nav><a class="toplink" href="/admin/storage">🗄 存储设置</a>';
  html += '<a class="toplink" href="/admin/config">⚙️ 提交设置</a>';
  html += '<a class="toplink" href="/admin/names">👥 名单管理</a></nav>';
  html += '<p class="meta">当前后端：<b>' + escapeHtml(String(store.backend).toUpperCase() + (store.backend === 'b2' ? ' (Cloudflare 免流)' : '')) + '</b></p></header>';
  html += deadlineHtml;

  var usableGrants = grants.filter(function (x) { return !x.used; });
  html += '<section id="grants" class="glass card"><div class="section-head"><h2>🔑 临时提交凭证</h2><span class="pill">一次性</span></div>';
  html += '<p class="meta" style="font-size:13px;color:#687892;margin:0 0 12px">截止后学生凭凭证可补交一次，提交成功即自动作废。凭证只是「绕过截止时间」，手动关闭提交时仍然拒绝。</p>';
  html += '<form method="POST" action="/admin/grant-add" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px">';
  html += '<input type="hidden" name="token" value="' + at + '">';
  html += '<input name="note" placeholder="备注（可选，如：张三补交）" style="flex:1;min-width:200px">';
  html += '<button type="submit" class="btn btn-primary btn-xs">＋ 生成凭证</button></form>';
  if (!grants.length) {
    html += '<p class="meta" style="font-size:13px">暂无凭证，点上面按钮生成一个发给学生即可。</p>';
  } else {
    html += '<ul style="list-style:none;padding:0;margin:0;font-size:13px">';
    for (var gi = 0; gi < grants.length; gi++) {
      var gr = grants[gi];
      var gid = escapeHtml(gr.id);
      html += '<li style="padding:9px 0;border-top:1px solid var(--dash-border);display:flex;gap:8px;align-items:center;flex-wrap:wrap">';
      html += '<code style="word-break:break-all;flex:1;min-width:220px">' + gid + '</code>';
      html += gr.used
        ? '<span style="color:#888;white-space:nowrap">已使用</span>'
        : '<span style="color:#159a68;font-weight:700;white-space:nowrap">可用</span>';
      html += '<button type="button" class="btn btn-ghost btn-xs" onclick="copyGrant(this,\'' + gid + '\')">复制</button>';
      html += '<form method="POST" action="/admin/grant-delete" style="display:inline;margin:0">' +
        '<input type="hidden" name="token" value="' + at + '">' +
        '<input type="hidden" name="id" value="' + gid + '">' +
        '<button type="submit" class="btn btn-danger-ghost btn-xs">删除</button></form>';
      if (gr.note || gr.usedBy) {
        html += '<span style="width:100%;color:#888;font-size:12px">' +
          escapeHtml(gr.note ? '备注：' + gr.note : '') +
          (gr.usedBy ? ' · 使用组：' + escapeHtml(gr.usedBy) : '') + '</span>';
      }
      html += '</li>';
    }
    html += '</ul>';
  }
  html += '<p class="meta" style="font-size:12px;margin-top:10px">当前可用 <b>' + usableGrants.length + '</b> 个，共 ' + grants.length + ' 个。</p></section>';

  html += '<div class="stat"><p>📊 已上传：' + fmt(totalSize) + ' | <b style="color:#c00">未下载：' + fmt(undownloadedSize) + '</b></p>';
  html += '<p>✅ 已交：' + allSids.size + ' 人 | ❌ 未交：' + missing.length + ' 人</p></div>';
  if (missing.length) {
    html += '<p style="font-size:13px;color:#c00">❌ 未交名单：' +
    escapeHtml(missing.map(function (x) { return labelOf(nmap, x); }).join('、')) + '</p>';
  }

  html += '<div id="zbar" style="border:1px solid #28a745;background:#f6fff9;padding:12px 16px;border-radius:8px;margin:12px 0">';
  html += '<b>📦 批量下载：</b> ';
  html += '<button type="button" onclick="zAll(true)" class="btn btn-ghost btn-xs">全选</button>';
  html += '<button type="button" onclick="zAll(false)" class="btn btn-ghost btn-xs">清空</button>';
  html += '<button type="button" onclick="zUndownloaded()" class="btn btn-ghost btn-xs">仅选未下载</button>';
  html += '<button type="button" onclick="zSubmit(false)" class="btn btn-primary btn-xs">⬇ 下载选中 (ZIP)</button>';
  html += '<button type="button" onclick="zSubmit(true)" class="btn btn-ok btn-xs">⬇ 下载选中并标记已下载</button>';
  html += '<span id="zcnt" style="margin-left:10px;color:#555;font-size:14px">已选 0 个文件</span>';
  html += '<div id="zmsg" style="margin-top:8px;color:#c00;font-size:14px"></div>';
  html += '</div>';

  var fileIndex = 0;
  for (var i = 0; i < groupDataList.length; i++) {
    var gn2 = groupDataList[i].name;
    var g2 = groupDataList[i].data;
    var gn2e = escapeHtml(gn2);
    html += '<div style="border:1px solid #ddd;padding:10px;margin:10px 0;border-radius:6px">';
    html += '<h3>📦 <b>' + gn2e + '</b>';
    html += ' <label style="font-size:12px;font-weight:normal;margin-left:10px;cursor:pointer"><input type="checkbox" onclick="zToggleGroup(this,' + i + ')"> 选中本组</label>';
    html += '<form method="POST" action="/admin/delete/' + encodeURIComponent(gn2) + '" onsubmit="return confirm(\'删除整组？\')" style="display:inline;margin-left:10px">' +
    '<input type="hidden" name="token" value="' + at + '">' +
    '<button type="submit" class="btn btn-danger-ghost btn-xs">🗑 删除整组</button></form></h3>';
    html += '<div style="background:#f5f5f5;padding:8px;border-radius:4px;margin-bottom:8px"><b>成员：</b> ';
    for (var j = 0; j < (g2.members || []).length; j++) {
      var sid = g2.members[j];
      var sLb = escapeHtml(labelOf(nmap, sid));
      html += '<span style="display:inline-block;margin:2px 4px;padding:2px 6px;background:#e0e8ff;border-radius:3px">' + sLb;
      html += '<form method="POST" action="/admin/edit-members" onsubmit="return confirm(\'移除该成员？\')" style="display:inline;margin:0 0 0 4px">' +
      '<input type="hidden" name="token" value="' + at + '">' +
      '<input type="hidden" name="action" value="remove">' +
      '<input type="hidden" name="group" value="' + gn2e + '">' +
      '<input type="hidden" name="remove" value="' + escapeHtml(sid) + '">' +
      '<button type="submit" class="btn btn-danger-ghost btn-icon">✕</button></form></span>';
    }
    if (!(g2.members || []).length) html += '<span style="color:#999">（无成员）</span>';
    html += '</div><ul style="margin:4px 0;padding-left:20px">';
    for (var j = 0; j < (g2.files || []).length; j++) {
      var f = g2.files[j];
      var dn = buildDownloadName(nmap, f.key, f.originalName) || (gn2 + '_' + f.originalName);
      var idx = fileIndex++;
      html += '<li><input type="checkbox" class="zf" data-i="' + idx + '" data-k="' + encodeURIComponent(f.key) + '" data-n="' + encodeURIComponent(dn) + '" data-dl="' + (f.downloaded ? '1' : '0') + '" onchange="zCount()" style="margin-right:6px">';
      html += '[' + escapeHtml(f.submitType || '?') + '] <a href="/admin/download/' + encodeURIComponent(f.key) + '?as=' + encodeURIComponent(dn) + '">' + escapeHtml(f.originalName) + '</a> (' + ((f.size||0)/1024/1024).toFixed(1) + 'MB) ';
      if (f.downloaded) {
        html += '<span style="color:green;font-size:12px">✅已下载</span>';
      } else {
        html += '<form method="POST" action="/admin/mark-downloaded/' + encodeURIComponent(f.key) + '" onsubmit="return confirm(\'标记已下载？\')" style="display:inline;margin:0">' +
        '<input type="hidden" name="token" value="' + at + '">' +
        '<button type="submit" class="btn btn-ghost btn-xs">⬇️标记</button></form>';
      }
      html += '<form method="POST" action="/admin/delete-file/' + encodeURIComponent(f.key) + '" onsubmit="return confirm(\'仅删除该文件？\')" style="display:inline;margin:0 0 0 6px">' +
      '<input type="hidden" name="token" value="' + at + '">' +
      '<button type="submit" class="btn btn-danger-ghost btn-xs">❌删</button></form></li>';
    }
    html += '</ul></div>';
  }

  var groupsJson = JSON.stringify(groupDataList.map(function (x) { return x.data.files || []; }))
  .replace(/</g, "\\u003c");
  html += '<script>';
  html += 'function copyGrant(btn,id){var done=function(){btn.textContent="已复制";setTimeout(function(){btn.textContent="复制"},1500);};' +
    'if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(id).then(done,function(){prompt("手动复制：",id)})}else{prompt("手动复制：",id)}}';
  html += 'var GROUPS=' + groupsJson + ';';
  html += 'var ADMIN_TOKEN="' + at + '";';
  html += 'function zBoxes(){return document.querySelectorAll(".zf");}';
  html += 'function zCount(){var n=0;zBoxes().forEach(function(b){if(b.checked)n++;});document.getElementById("zcnt").textContent="已选 "+n+" 个文件";}';
  html += 'function zAll(v){zBoxes().forEach(function(b){b.checked=v;});zCount();}';
  html += 'function zUndownloaded(){zBoxes().forEach(function(b){b.checked=(b.dataset.dl!=="1");});zCount();}';
  html += 'function zToggleGroup(el,i){var ks=(GROUPS[i]||[]).map(function(f){return encodeURIComponent(f.key);});zBoxes().forEach(function(b){if(ks.indexOf(b.dataset.k)>=0)b.checked=el.checked;});zCount();}';
  html += 'function zSubmit(mark){';
  html += '  var sel=[];zBoxes().forEach(function(b){if(b.checked)sel.push({k:decodeURIComponent(b.dataset.k),n:decodeURIComponent(b.dataset.n)});});';
  html += '  if(!sel.length){document.getElementById("zmsg").textContent="请先勾选文件";return;}';
  html += '  document.getElementById("zmsg").style.color="#555";';
  html += '  document.getElementById("zmsg").textContent="正在打包 "+sel.length+" 个文件，请勿关闭页面...";';
  html += '  var form=document.createElement("form");form.method="POST";form.action="/admin/download-zip";';
  html += '  var im=document.createElement("input");im.type="hidden";im.name="mark";im.value=mark?"1":"0";form.appendChild(im);';
  html += '  var it=document.createElement("input");it.type="hidden";it.name="token";it.value=ADMIN_TOKEN;form.appendChild(it);';
  html += '  sel.forEach(function(s){var a=document.createElement("input");a.type="hidden";a.name="k";a.value=s.k;form.appendChild(a);';
  html += '    var b=document.createElement("input");b.type="hidden";b.name="n";b.value=s.n;form.appendChild(b);});';
  html += '  document.body.appendChild(form);form.submit();document.body.removeChild(form);';
  html += '  setTimeout(function(){var m=document.getElementById("zmsg");if(m)m.textContent="下载已开始，完成后页面可继续使用。";},3000);';
  html += '}';
  html += '</script></main></body></html>';
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
}

async function handleAdminNames(req, env) {
  if (req.method === "GET" && !await authOk(req, env)) return basicChallenge();
  var origin = new URL(req.url).origin;
  var nmap = await getNameMap(env);
  var at = await makeAdminToken(env);

  if (req.method === "GET") {
    var preview = {};
    var keys = Object.keys(nmap).sort(function (a, b) {
      var na = Number(a), nb = Number(b);
      if (isNaN(na) || isNaN(nb)) return a < b ? -1 : 1;
      return na - nb;
    });
    for (var i = 0; i < keys.length; i++) preview[keys[i]] = nmap[keys[i]];

    var html = '<!DOCTYPE html><html><head>' + uiHead('名单管理') + '</head>';
    html += '<body class="app admin"><div class="aurora" aria-hidden="true"><span></span><span></span></div><main class="shell shell-wide">';
    html += '<header class="hero"><div class="brand"><span class="dot"></span> 管理后台</div><h2>👥 学号 → 姓名 名单</h2></header>';
    html += '<p style="color:#555;font-size:14px">粘贴 JSON 对象，键为学号、值为姓名。保存后，后台、提交页、下载文件名、ZIP 内路径中的学号都会显示为「学号_姓名」。</p>';
    html += '<form method="POST" action="/admin/names"><input type="hidden" name="token" value="' + at + '">';
    html += '<textarea name="json" rows="14" style="width:100%;box-sizing:border-box;padding:8px;font-family:monospace;font-size:14px;border:1px solid #ccc;border-radius:6px">' + escapeHtml(JSON.stringify(preview, null, 2)) + '</textarea>';
    html += '<p><button type="submit" class="btn btn-primary">💾 保存名单</button> ';
    html += '<button type="submit" name="clear" value="1" onclick="return confirm(\'清空名单？所有显示将回退为纯学号\')" class="btn btn-danger">🗑 清空</button></p>';
    html += '</form><p>当前已登记 <b>' + keys.length + '</b> 人。</p>';
    html += '<p style="color:#888;font-size:13px">允许 // 注释、单引号与尾部逗号；姓名中的 / \\ : * ? " &lt; &gt; | 和空格会替换为下划线，单个姓名最多 30 字符。</p>';
    html += '<p><a class="toplink" href="/admin">← 返回</a></p></main></body></html>';
    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  if (req.method === "POST") {
    var fd = await req.formData();
    if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
    if (fd.get("clear") === "1") {
      await env.GROUP_KV.delete("namemap");
      return Response.redirect(origin + "/admin/names", 302);
    }
    var txt = String(fd.get("json") || "").trim();
    if (!txt) {
      await env.GROUP_KV.delete("namemap");
      return Response.redirect(origin + "/admin/names", 302);
    }
    var cleaned = txt.split("\n").map(function (line) {
      var ci = line.indexOf("//");
      return ci >= 0 ? line.slice(0, ci) : line;
    }).join("\n")
    .replace(/'/g, '"')
    .replace(/,\s*([}\]])/g, "$1");
    var obj;
    try { obj = JSON.parse(cleaned); }
    catch (e) {
      return new Response("❌ JSON 解析失败：" + escapeHtml(e.message) + "<p><a href='/admin/names'>← 返回修改</a></p>", {
        status: 400, headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
      return new Response('❌ 顶层必须是一个 JSON 对象，例如 {"1": "张三"}', { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
    var out = {};
    var bad = [];
    for (const k of Object.keys(obj)) {
      var sid = String(k).trim();
      var nm = String(obj[k] == null ? "" : obj[k]).trim().replace(/[\/\\:*?"<>|\s]/g, "_");
      if (!/^\d{1,10}$/.test(sid)) { bad.push("键「" + k + "」不是纯数字学号"); continue; }
      if (!nm) { bad.push("学号 " + sid + " 的姓名为空"); continue; }
      out[sid] = nm.slice(0, 30);
    }
    if (bad.length) {
      return new Response("❌ 有 " + bad.length + " 处问题：<br>" + bad.map(escapeHtml).join("<br>") + "<p><a href='/admin/names'>← 返回修改</a></p>", {
        status: 400, headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }
    await env.GROUP_KV.put("namemap", JSON.stringify(out));
    return Response.redirect(origin + "/admin", 302);
}
return new Response("Method Not Allowed", { status: 405 });
}

async function handleAdminConfig(req, env) {
  if (req.method === "GET" && !await authOk(req, env)) return basicChallenge();
  var at = await makeAdminToken(env);
  if (req.method === "GET") {
    var cfg = await getConfig(env);
    var html = '<!DOCTYPE html><html><head>' + uiHead('提交设置') + '</head>' + '<body class="app admin"><div class="aurora" aria-hidden="true"><span></span><span></span></div><main class="shell shell-wide">';
    html += '<header class="hero"><div class="brand"><span class="dot"></span> 管理后台</div><h2>⚙️ 提交设置</h2></header><form method="POST" action="/admin/config"><input type="hidden" name="token" value="' + at + '">';
    html += '<p><label><input type="checkbox" name="groupMode" ' + (cfg.groupMode ? 'checked' : '') + '> 使用小组制</label></p>';
    html += '<p><label><input type="checkbox" name="submissionOpen" ' + (cfg.submissionOpen ? 'checked' : '') + '> 开放提交（关闭后服务端也会拒绝，不只隐藏表单）</label></p>';
    html += '<p>每组人数：<input type="number" name="groupSize" min="1" max="10" value="' + Number(cfg.groupSize) + '" style="width:60px"></p>';
    html += '<p>应提交学号名单：<br><input name="expectedSids" placeholder="留空 = 默认 1~48" value="' + escapeHtml(cfg.expectedSids || "") + '" style="width:100%;max-width:520px"></p>';
    html += '<p class="meta" style="font-size:12.5px">逗号 / 空格 / 顿号分隔，也支持区间如 <code>1~30</code>；只有名单内的学号能提交。</p>';
    html += '<p><label><input type="checkbox" name="testMode" ' + (cfg.testMode ? 'checked' : '') + '> 🧪 测试模式（允许学号 <code>-1</code>，需单独提交）</label></p>';
    html += '<p class="meta" style="font-size:12.5px">关闭时填 <code>-1</code> 会跳转彩蛋页；开启时 <code>-1</code> 只在名单之外额外放行。</p>';
    html += '<p>提交类型：<br>';
    ['video','audio','image','ppt','doc'].forEach(function(t) {
      html += '<label style="margin-right:12px"><input type="checkbox" name="types" value="' + t + '" ' + (Array.isArray(cfg.submitTypes) && cfg.submitTypes.indexOf(t) >= 0 ? 'checked' : '') + '> ' + t + '</label>';
    });
    html += '</p><button type="submit" class="btn btn-primary">💾 保存</button></form><p><a class="toplink" href="/admin">← 返回</a></p></main></body></html>';
    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  if (req.method === "POST") {
    var fd = await req.formData();
    if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
    var cfg = {
      groupMode: fd.get("groupMode") === "on",
      groupSize: Math.max(1, Math.min(10, Number(fd.get("groupSize") || 4))),
      submitTypes: fd.getAll("types").map(String),
      submissionOpen: fd.get("submissionOpen") === "on",
      expectedSids: String(fd.get("expectedSids") || "").slice(0, 2000),
      testMode: fd.get("testMode") === "on"
    };
    if (cfg.submitTypes.length === 0) return new Response("至少选择一种提交类型", { status: 400 });
    await env.GROUP_KV.put("config", JSON.stringify(cfg));
    return Response.redirect(new URL(req.url).origin + "/admin", 302);
  }
  return new Response("Method Not Allowed", { status: 405 });
}

async function handleSetDeadline(req, env) {
  var url = new URL(req.url);
  if (req.method !== "POST") return Response.redirect(url.origin + "/admin", 302);
  var fd = await req.formData();
  if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
  if (fd.get("action") === "clear") {
    await env.GROUP_KV.delete("deadline");
  } else {
    var ts = null;
    if (fd.get("at") === "now") ts = Date.now();
    else if (fd.get("at_ts")) ts = Number(fd.get("at_ts"));
    if (Number.isFinite(ts) && ts > 0) await env.GROUP_KV.put("deadline", String(ts));
  }
  return Response.redirect(url.origin + "/admin", 302);
}

async function handleClearSubmissions(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  var fd = await req.formData();
  if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
  var keys = await listGroupKeys(env);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var g = JSON.parse(await env.GROUP_KV.get(k) || "{}");
    for (var j = 0; j < (g.members || []).length; j++) await env.GROUP_KV.delete("sid:" + g.members[j]);
    await env.GROUP_KV.delete(k);
  }
  return Response.redirect(new URL(req.url).origin + "/admin", 302);
}

async function handleEditMembers(req, env) {
  var origin = new URL(req.url).origin;
  if (req.method !== "POST") return Response.redirect(origin + "/admin", 302);
  var fd = await req.formData();
  if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
  var action = String(fd.get("action") || "");
  var target = String(fd.get("group") || "").trim();
  var sid = String(fd.get(action === "remove" ? "remove" : "add_sid") || "").trim();
  if ((!isValidStudentId(sid) && sid !== "-1") || !target) return Response.redirect(origin + "/admin", 302);
  var gRaw = await env.GROUP_KV.get("grp:" + target);
  if (!gRaw) return new Response("组不存在", { status: 404 });
  var g = JSON.parse(gRaw);
  if (action === "remove") {
    g.members = (g.members || []).filter(function (s) { return s !== sid; });
    await env.GROUP_KV.delete("sid:" + sid);
    await env.GROUP_KV.put("grp:" + target, JSON.stringify(g));
  } else {
    var ex = await env.GROUP_KV.get("sid:" + sid);
    if (ex && ex !== target) return new Response("学号 " + sid + " 已在「" + escapeHtml(ex) + "」组", { status: 409 });
    if ((g.members || []).indexOf(sid) < 0) {
      g.members = (g.members || []).concat([sid]);
      await env.GROUP_KV.put("grp:" + target, JSON.stringify(g));
      await env.GROUP_KV.put("sid:" + sid, target);
    }
  }
  return Response.redirect(origin + "/admin", 302);
}

async function handleAdminStorage(req, env) {
  if (req.method === "GET" && !await authOk(req, env)) return basicChallenge();
  var at = await makeAdminToken(env);
  var store = await getStorageConfig(env);
  if (req.method === "GET") {
    var v = function (s) { return escapeHtml(s); };
    var html = '<!DOCTYPE html><html><head>' + uiHead('存储设置') + '</head>';
    html += '<body class="app admin"><div class="aurora" aria-hidden="true"><span></span><span></span></div><main class="shell shell-wide">';
    html += '<header class="hero"><div class="brand"><span class="dot"></span> 管理后台</div><h2>🗄 存储设置</h2></header>';
    html += '<form method="POST" action="/admin/storage"><input type="hidden" name="token" value="' + at + '">';
    html += '<p><b>存储后端：</b> ';
    html += '<label><input type="radio" name="backend" value="s3" ' + (store.backend === "s3" ? "checked" : "") + '> S3</label> ';
    html += '<label><input type="radio" name="backend" value="webdav" ' + (store.backend === "webdav" ? "checked" : "") + '> WebDAV</label> ';
    html += '<label><input type="radio" name="backend" value="b2" ' + (store.backend === "b2" ? "checked" : "") + '> B2 (S3 兼容)</label></p>';
    html += '<fieldset style="margin:12px 0;padding:12px;border:1px solid #ccc;border-radius:6px"><legend><b>S3</b></legend>';
    html += '<p>Endpoint:<br><input name="s3_endpoint" style="width:100%;padding:4px" value="' + v(store.s3.endpoint) + '"></p>';
    html += '<p>Bucket:<br><input name="s3_bucket" value="' + v(store.s3.bucket) + '"></p>';
    html += '<p>Region:<br><input name="s3_region" value="' + v(store.s3.region) + '"></p>';
    html += '<p>AccessKeyId:<br><input name="s3_access" style="width:100%;padding:4px" value="' + v(store.s3.accessKeyId) + '"></p>';
    html += '<p>SecretKey:<br><input name="s3_secret" type="password" style="width:100%;padding:4px" placeholder="留空=不修改"></p></fieldset>';
    html += '<fieldset style="margin:12px 0;padding:12px;border:1px solid #ccc;border-radius:6px"><legend><b>WebDAV</b></legend>';
    html += '<p>Base URL:<br><input name="dav_url" style="width:100%;padding:4px" value="' + v(store.webdav.baseUrl) + '"></p>';
    html += '<p>用户名:<br><input name="dav_user" value="' + v(store.webdav.username) + '"></p>';
    html += '<p>密码:<br><input name="dav_pass" type="password" placeholder="留空=不修改"></p></fieldset>';
    html += '<fieldset style="margin:12px 0;padding:12px;border:1px solid #ff9900;border-radius:6px;background:#fffaf0"><legend><b>🪣 Backblaze B2</b></legend>';
    html += '<p>Application Key ID:<br><input name="b2_key_id" style="width:100%;padding:4px" value="' + v(store.b2.applicationKeyId) + '"></p>';
    html += '<p>Application Key:<br><input name="b2_key" type="password" style="width:100%;padding:4px" placeholder="留空=不修改"></p>';
    html += '<p>Bucket Name:<br><input name="b2_bucket" style="width:100%;padding:4px" value="' + v(store.b2.bucketName) + '"></p>';
    html += '<p>Region:<br><input name="b2_region" style="width:200px;padding:4px" value="' + v(store.b2.region) + '"></p>';
    html += '<p>S3 Endpoint:<br><input name="b2_s3_endpoint" style="width:100%;padding:4px" value="' + v(store.b2.s3Endpoint) + '"></p></fieldset>';
    html += '<button type="submit" class="btn btn-primary">💾 保存</button></form><hr>';
    html += '<button onclick="testConn()" class="btn btn-ghost">🔌 测试连接</button>';
    html += '<pre id="out" style="margin-top:12px;padding:12px;background:#f5f5f5;border-radius:6px"></pre>';
    html += '<p><a class="toplink" href="/admin">← 返回</a></p>';
    html += '<script>async function testConn(){document.getElementById("out").textContent="测试中...";var r=await fetch("/admin/test-storage",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"token="+encodeURIComponent("' + at + '")});document.getElementById("out").textContent=await r.text();}</script>';
    html += '</main></body></html>';
    return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  if (req.method === "POST") {
    var fd = await req.formData();
    if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
    var cur = await getStorageConfig(env);
    var region = String(fd.get("b2_region") || "us-west-004");
    var next = {
      backend: fd.get("backend") || "s3",
      s3: {
        endpoint: String(fd.get("s3_endpoint") || ""),
        bucket: String(fd.get("s3_bucket") || ""),
        region: String(fd.get("s3_region") || "auto"),
        accessKeyId: String(fd.get("s3_access") || ""),
        secretAccessKey: String(fd.get("s3_secret") || cur.s3.secretAccessKey)
      },
      webdav: {
        baseUrl: String(fd.get("dav_url") || ""),
        username: String(fd.get("dav_user") || ""),
        password: String(fd.get("dav_pass") || cur.webdav.password)
      },
      b2: {
        applicationKeyId: String(fd.get("b2_key_id") || ""),
        applicationKey: String(fd.get("b2_key") || cur.b2.applicationKey),
        bucketName: String(fd.get("b2_bucket") || ""),
        region: region,
        s3Endpoint: String(fd.get("b2_s3_endpoint") || `https://s3.${region}.backblazeb2.com`)
      }
    };
    if (!["s3","webdav","b2"].includes(next.backend)) next.backend = "s3";
    await env.GROUP_KV.put("storage", JSON.stringify(next));
    return Response.redirect(new URL(req.url).origin + "/admin/storage", 302);
  }
  return new Response("Method Not Allowed", { status: 405 });
}

async function testB2(b2Config) {
  const { applicationKeyId, applicationKey, bucketName, region, s3Endpoint } = b2Config;
  if (!applicationKeyId || !applicationKey || !bucketName || !region) {
    return { ok: false, msg: "❌ 缺少必填字段" };
  }
  const endpoint = (s3Endpoint || `https://s3.${region}.backblazeb2.com`).replace(/\/+$/, '');
  const client = new S3Client({ endpoint, bucket: bucketName, region, accessKeyId: applicationKeyId, secretAccessKey: applicationKey });
  return client.testConnection();
}

async function handleTestStorage(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  var fd = await req.formData().catch(() => null);
  if (!await adminOk(req, env, fd && fd.get("token"))) return basicChallenge();
  var store = await getStorageConfig(env);
  if (store.backend === "b2") {
    const result = await testB2(store.b2);
    return new Response(result.msg);
  }
  if (store.backend === "webdav") {
    try {
      var testUrl = store.webdav.baseUrl.replace(/\/+$/, "") + "/";
      var res = await fetch(testUrl, {
        method: "PROPFIND",
        headers: { "Authorization": "Basic " + btoa(store.webdav.username + ":" + store.webdav.password), "Depth": "0", "Content-Type": "application/xml" },
                            body: '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>'
      });
      if (res.ok || res.status === 207) return new Response("✅ WebDAV 连接成功");
      if (res.status === 401) return new Response("❌ WebDAV 认证失败");
      return new Response("❌ WebDAV 返回 " + res.status);
    } catch (e) { return new Response("❌ " + e.message); }
  }
  try {
    var s3 = new S3Client(store.s3);
    var ok = await s3.testConnection ? (await s3.testConnection()).ok : false;
    return new Response(ok ? "✅ S3 连接成功" : "❌ S3 连接失败");
  } catch (e) { return new Response("❌ " + e.message); }
}

async function handleDeleteGroup(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  var fd = await req.formData();
  if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
  var group = decodeURIComponent(new URL(req.url).pathname.slice("/admin/delete/".length));
  var gRaw = await env.GROUP_KV.get("grp:" + group);
  if (!gRaw) return new Response("组不存在", { status: 404 });
  var g = JSON.parse(gRaw);
  var store = await getStorageConfig(env);
  for (var i = 0; i < (g.files || []).length; i++) await deleteStorageObject(store, g.files[i].key);
  for (var i = 0; i < (g.members || []).length; i++) await env.GROUP_KV.delete("sid:" + g.members[i]);
  await env.GROUP_KV.delete("grp:" + group);
  return Response.redirect(new URL(req.url).origin + "/admin", 302);
}

async function handleDeleteFile(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  var fd = await req.formData();
  if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
  var key = decodeURIComponent(new URL(req.url).pathname.slice("/admin/delete-file/".length));
  var store = await getStorageConfig(env);
  var keys = await listGroupKeys(env);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var gRaw = await env.GROUP_KV.get(k);
    if (!gRaw) continue;
    var g = JSON.parse(gRaw);
    if ((g.files || []).find(function (f) { return f.key === key; })) {
      g.files = g.files.filter(function (f) { return f.key !== key; });
      await env.GROUP_KV.put(k, JSON.stringify(g));
      break;
    }
  }
  await deleteStorageObject(store, key);
  return Response.redirect(new URL(req.url).origin + "/admin", 302);
}

async function handleMarkDownloaded(req, env) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  var fd = await req.formData();
  if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();
  var key = decodeURIComponent(new URL(req.url).pathname.slice("/admin/mark-downloaded/".length));
  var keys = await listGroupKeys(env);
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var gRaw = await env.GROUP_KV.get(k);
    if (!gRaw) continue;
    var g = JSON.parse(gRaw);
    var changed = false;
    for (var j = 0; j < (g.files || []).length; j++) {
      if (g.files[j].key === key && !g.files[j].downloaded) { g.files[j].downloaded = true; changed = true; }
    }
    if (changed) { await env.GROUP_KV.put(k, JSON.stringify(g)); break; }
  }
  return Response.redirect(new URL(req.url).origin + "/admin", 302);
}

async function handleDownload(req, env) {
  if (!await authOk(req, env)) return basicChallenge();
  var key = decodeURIComponent(new URL(req.url).pathname.slice("/admin/download/".length));
  var as = buildDownloadName(await getNameMap(env), key, null)
  || new URL(req.url).searchParams.get("as") || "file";
  var store = await getStorageConfig(env);

  if (store.backend === "webdav") {
    var dav = store.webdav;
    var base = String(dav.baseUrl || "").replace(/\/+$/, "");
    var upstream = await fetch(base + "/" + encodeStorageKey(key), {
      headers: { Authorization: "Basic " + btoa(dav.username + ":" + dav.password) }
    });
    if (!upstream.ok) return new Response("下载失败: " + upstream.status, { status: 502 });
    var headers = new Headers({
      "Content-Type": upstream.headers.get("Content-Type") || "application/octet-stream",
                              "Content-Disposition": "attachment; filename*=UTF-8''" + encodeURIComponent(as)
    });
    var len = upstream.headers.get("Content-Length");
    if (len) headers.set("Content-Length", len);
    return new Response(upstream.body, { headers: headers });
  }

  var client = storageClient(store);
  if (!client) return new Response("存储未配置", { status: 500 });
  var signedUrl = await client.getSignedDownloadUrl(key, 3600, as);
  if (store.backend === "s3") return Response.redirect(signedUrl, 302);
  var b2res = await fetch(signedUrl);
  if (!b2res.ok) return new Response("B2 下载失败: " + b2res.status, { status: 502 });
  var b2headers = new Headers({
    "Content-Type": b2res.headers.get("Content-Type") || "application/octet-stream",
                              "Content-Disposition": "attachment; filename*=UTF-8''" + encodeURIComponent(as)
  });
  var b2len = b2res.headers.get("Content-Length");
  if (b2len) b2headers.set("Content-Length", b2len);
  return new Response(b2res.body, { headers: b2headers });
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32Update(crc, bytes) {
  let c = crc;
  for (let i = 0; i < bytes.length; i++) {
    c = (c >>> 8) ^ CRC_TABLE[(c ^ bytes[i]) & 0xff];
  }
  return c >>> 0;
}

function dosTime(d) {
  const t = ((d.getHours() & 0x1f) << 11) | ((d.getMinutes() & 0x3f) << 5) | ((d.getSeconds() / 2) & 0x1f);
  const dt = (((d.getFullYear() - 1980) & 0x7f) << 9) | (((d.getMonth() + 1) & 0x0f) << 5) | (d.getDate() & 0x1f);
  return { time: t, date: dt };
}

class ZipStreamer {
  constructor(writer) {
    this.w = writer;
    this.offset = 0;
    this.entries = [];
    this.closed = false;
  }

  async _write(bytes) {
    const buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    await this.w.write(buf);
    this.offset += buf.length;
  }

  _u16(n) { return new Uint8Array([n & 0xff, (n >> 8) & 0xff]); }
  _u32(n) { return new Uint8Array([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff]); }

  async addFile(name, entry) {
    const nameBytes = new TextEncoder().encode(name);
    const { time, date } = dosTime(new Date());
    const sizeHint = Number(entry.size) || 0;
    if (sizeHint > 0xffffffff || this.offset + sizeHint + nameBytes.length + 46 > 0xffffffff) {
      throw new Error("单个文件超过 4GB 或压缩包过大");
    }
    const localOffset = this.offset;

    await this._write(concatBytes([
      this._u32(0x04034b50),
                                  this._u16(20),
                                  this._u16(0x0808),
                                  this._u16(0),
                                  this._u16(time), this._u16(date),
                                  this._u32(0), this._u32(0), this._u32(0),
                                  this._u16(nameBytes.length), this._u16(0),
    ]));
    await this._write(nameBytes);

    let crc = 0xffffffff;
    let size = 0;
    const reader = entry.stream.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      crc = crc32Update(crc, chunk);
      size += chunk.length;
      await this._write(chunk);
    }
    crc = (crc ^ 0xffffffff) >>> 0;
    if (size > 0xffffffff || this.offset > 0xffffffff) throw new Error("文件超过 4GB");

    await this._write(concatBytes([
      this._u32(0x08074b50),
                                  this._u32(crc), this._u32(size), this._u32(size),
    ]));

    this.entries.push({ nameBytes, crc, size, offset: localOffset, time, date });
  }

  async finish() {
    if (this.closed) return;
    const cdStart = this.offset;
    let cdSize = 0;
    for (const e of this.entries) {
      const part = concatBytes([
        this._u32(0x02014b50),
                               this._u16(20), this._u16(20),
                               this._u16(0x0808), this._u16(0),
                               this._u16(e.time), this._u16(e.date),
                               this._u32(e.crc), this._u32(e.size), this._u32(e.size),
                               this._u16(e.nameBytes.length),
                               this._u16(0), this._u16(0), this._u16(0), this._u16(0),
                               this._u32(0), this._u32(e.offset),
      ]);
      await this._write(part);
      cdSize += part.length;
      await this._write(e.nameBytes);
      cdSize += e.nameBytes.length;
    }
    if (cdSize > 0xffffffff || cdStart > 0xffffffff || this.entries.length > 0xffff) {
      throw new Error("压缩包超过 ZIP32 上限");
    }
    await this._write(concatBytes([
      this._u32(0x06054b50),
                                  this._u16(0), this._u16(0),
                                  this._u16(this.entries.length), this._u16(this.entries.length),
                                  this._u32(cdSize), this._u32(cdStart),
                                  this._u16(0),
    ]));
    this.closed = true;
    await this.w.close();
  }

  async abort(err) {
    try { await this.w.abort(err); } catch (_) {}
  }
}

function concatBytes(list) {
  let total = 0;
  for (const b of list) total += b.length;
  const out = new Uint8Array(total);
  let p = 0;
  for (const b of list) { out.set(b, p); p += b.length; }
  return out;
}

async function openStorageStream(store, key) {
  if (store.backend === "webdav") {
    const dav = store.webdav;
    const base = String(dav.baseUrl || "").replace(/\/+$/, "");
    const res = await fetch(base + "/" + encodeStorageKey(key), {
      headers: { Authorization: "Basic " + btoa(dav.username + ":" + dav.password) }
    });
    if (!res.ok || !res.body) throw new Error("WebDAV 读取失败 " + res.status);
    return { stream: res.body, size: Number(res.headers.get("Content-Length")) || 0 };
  }
  const client = storageClient(store);
  if (!client) throw new Error("存储未配置");
  const url = await client.getSignedDownloadUrl(key, 3600, null);
  const res = await fetch(url);
  if (!res.ok || !res.body) throw new Error("对象存储读取失败 " + res.status);
  return { stream: res.body, size: Number(res.headers.get("Content-Length")) || 0 };
}

async function handleDownloadZip(req, env, ctx) {
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
  let fd;
  try { fd = await req.formData(); } catch (_) { return new Response("请求解析失败", { status: 400 }); }
  if (!await adminOk(req, env, fd.get("token"))) return basicChallenge();

  const keys = fd.getAll("k").map(String);
  const names = fd.getAll("n").map(String);
  const mark = String(fd.get("mark") || "0") === "1";
  const nmap = await getNameMap(env);

  if (!keys.length) return new Response("未选择文件", { status: 400 });
  if (keys.length > 500) return new Response("单次最多打包 500 个文件", { status: 400 });

  const store = await getStorageConfig(env);
  const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const zipName = `作业批量下载_${stamp}_${keys.length}个文件.zip`;

  const { readable, writable } = new TransformStream();
  const zip = new ZipStreamer(writable.getWriter());

  const task = (async () => {
    let okCount = 0;
    const used = new Set();
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      let name = (buildDownloadName(nmap, key, null) || names[i] || key)
      .replace(/[\\/:*?"<>|]/g, "_");
      if (used.has(name)) {
        const dot = name.lastIndexOf(".");
        name = dot > 0 ? name.slice(0, dot) + `_${i + 1}` + name.slice(dot) : name + `_${i + 1}`;
      }
      used.add(name);
      try {
        const entry = await openStorageStream(store, key);
        await zip.addFile(name, entry);
        okCount++;
      } catch (e) {
        const msg = new TextEncoder().encode(`下载失败：${e.message || e}\n原始 Key：${key}\n`);
        await zip.addFile("下载失败/" + name + ".txt", { stream: byteStream(msg), size: msg.length });
      }
    }
    await zip.finish();

    if (mark && okCount > 0) {
      const groupKeys = await listGroupKeys(env);
      for (const k of groupKeys) {
        const raw = await env.GROUP_KV.get(k);
        if (!raw) continue;
        const g = JSON.parse(raw);
        let changed = false;
        for (const f of (g.files || [])) {
          if (keys.includes(f.key) && !f.downloaded) { f.downloaded = true; changed = true; }
        }
        if (changed) await env.GROUP_KV.put(k, JSON.stringify(g));
      }
    }
  })();

  const guarded = task.catch(async (err) => {
    console.error("ZIP 打包失败", err);
    await zip.abort(err);
  });
  if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(guarded);

  return new Response(readable, {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": "attachment; filename*=UTF-8''" + encodeURIComponent(zipName),
                      "Cache-Control": "no-store"
    }
  });
}
