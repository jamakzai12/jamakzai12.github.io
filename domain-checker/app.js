// Sending domain checker. Runs in the browser; DNS answers come from public
// DNS-over-HTTPS (Cloudflare first, Google as a backup). Nothing is stored.
"use strict";

const TYPES = { A: 1, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };
const SPF_LIMIT = 10;
const COMMON_SELECTORS = [
  "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
  "default", "mail", "dkim", "smtp", "zoho", "mxvault", "protonmail",
];
const PROVIDERS = [
  [/(^|\.)google(mail)?\.com$/, "Google Workspace"],
  [/\.mail\.protection\.outlook\.com$/, "Microsoft 365"],
  [/(^|\.)zoho\.(com|eu|in)$/, "Zoho Mail"],
  [/(^|\.)secureserver\.net$/, "GoDaddy"],
  [/(^|\.)ionos\.(com|de|co\.uk)$/, "IONOS"],
  [/(^|\.)protonmail\.ch$/, "Proton Mail"],
  [/(^|\.)mailgun\.org$/, "Mailgun"],
  [/(^|\.)messagingengine\.com$/, "Fastmail"],
  [/(^|\.)mxrouting\.net$/, "MXroute"],
];

const $ = (id) => document.getElementById(id);
const cache = new Map();

// ---------- DNS ----------

async function fetchJson(url, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { accept: "application/dns-json" } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function dns(name, type) {
  const key = `${name}|${type}`;
  if (cache.has(key)) return cache.get(key);
  const q = `name=${encodeURIComponent(name)}&type=${type}`;
  const p = fetchJson(`https://cloudflare-dns.com/dns-query?${q}`, 6000)
    .catch(() => fetchJson(`https://dns.google/resolve?${q}`, 6000))
    .then((r) => ({
      ok: r.Status === 0,
      nx: r.Status === 3,
      answers: (r.Answer || []).filter((a) => a.type === TYPES[type]),
    }));
  cache.set(key, p);
  return p;
}

// TXT data comes back quoted and sometimes split into several strings.
function txtValue(data) {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, "$1"));
  return parts.length ? parts.join("") : data;
}

async function txt(name) {
  const r = await dns(name, "TXT");
  return r.answers.map((a) => txtValue(a.data));
}

// ---------- Input ----------

function cleanDomain(raw) {
  let d = (raw || "").trim().toLowerCase();
  if (d.includes("@")) d = d.split("@").pop();
  d = d.replace(/^[a-z]+:\/\//, "").split(/[/?#:]/)[0].replace(/\.$/, "");
  if (d.startsWith("www.")) d = d.slice(4);
  return /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/.test(d) ? d : null;
}

// ---------- Checks ----------
// Each check returns { name, status: pass|check|fix, say, fix?, record?, extra? }

async function checkMx(domain) {
  const r = await dns(domain, "MX");
  const hosts = r.answers
    .map((a) => a.data.trim().split(/\s+/))
    .map(([pref, host]) => ({ pref: Number(pref), host: (host || "").replace(/\.$/, "").toLowerCase() }))
    .sort((a, b) => a.pref - b.pref);
  const record = hosts.map((h) => `${h.pref} ${h.host}`).join("\n");
  if (!hosts.length) {
    return {
      name: "MX", status: "fix",
      say: "No MX records, so replies to this domain have nowhere to go.",
      fix: "Add the MX records from your mail provider (Google Workspace, Microsoft 365, etc.).",
    };
  }
  if (hosts.length === 1 && (hosts[0].host === "" || hosts[0].host === ".")) {
    return { name: "MX", status: "fix", say: "This domain says it does not accept mail (null MX).", fix: "Remove the null MX and add your provider's MX records.", record };
  }
  const found = PROVIDERS.find(([re]) => hosts.some((h) => re.test(h.host)));
  return {
    name: "MX", status: "pass",
    say: found ? `Mail goes to ${found[1]}.` : `Mail goes to ${hosts[0].host}.`,
    record,
  };
}

function spfTerms(record) {
  return record.trim().split(/\s+/).slice(1);
}

// Counts DNS-querying terms (include, a, mx, ptr, exists, redirect), following
// include and redirect, as RFC 7208 section 4.6.4 does.
async function countSpfLookups(domain, seen = new Set(), depth = 0) {
  const out = { count: 0, problems: [] };
  if (depth > 10) { out.problems.push("includes nest too deep"); return out; }
  if (seen.has(domain)) { out.problems.push(`${domain} includes itself (loop)`); return out; }
  seen.add(domain);
  const recs = (await txt(domain)).filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (depth > 0 && recs.length === 0) { out.problems.push(`${domain} has no SPF record`); return out; }
  if (recs.length > 1) out.problems.push(`${domain} has ${recs.length} SPF records`);
  const terms = spfTerms(recs[0] || "");
  const hasAll = terms.some((t) => /^[+\-~?]?all$/i.test(t));
  for (const raw of terms) {
    const t = raw.replace(/^[+\-~?]/, "").toLowerCase();
    let target = null;
    if (t.startsWith("include:")) { out.count++; target = t.slice(8); }
    else if (t.startsWith("redirect=")) { if (hasAll) continue; out.count++; target = t.slice(9); }
    else if (/^(a|mx)([:/]|$)/.test(t) || /^ptr(:|$)/.test(t) || t.startsWith("exists:")) out.count++;
    if (target && !target.includes("%")) {
      const sub = await countSpfLookups(target, seen, depth + 1);
      out.count += sub.count;
      out.problems.push(...sub.problems);
    }
  }
  return out;
}

async function checkSpf(domain) {
  const recs = (await txt(domain)).filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (!recs.length) {
    return {
      name: "SPF", status: "fix",
      say: "No SPF record. Receivers can't tell which servers may send for this domain.",
      fix: "Add one TXT record from your provider, e.g. v=spf1 include:_spf.google.com ~all for Google Workspace.",
    };
  }
  if (recs.length > 1) {
    return {
      name: "SPF", status: "fix",
      say: `${recs.length} SPF records. Receivers treat that as an error, so SPF fails.`,
      fix: "Merge them into one record that starts with v=spf1.",
      record: recs.join("\n"),
    };
  }
  const record = recs[0];
  const terms = spfTerms(record);
  const all = terms.find((t) => /^[+\-~?]?all$/i.test(t));
  const { count, problems } = await countSpfLookups(domain);
  const meter = { used: count };
  if (count > SPF_LIMIT) {
    return { name: "SPF", status: "fix", say: `${count} DNS lookups. Over the limit of 10, so SPF fails.`, fix: "Remove includes for tools you no longer send from, or ask your provider for a flattened include.", record, meter };
  }
  if (all && /^\+?all$/i.test(all)) {
    return { name: "SPF", status: "fix", say: "Ends in +all, which lets any server send as you.", fix: "Change the ending to ~all (or -all).", record, meter };
  }
  if (problems.length) {
    return { name: "SPF", status: "check", say: `One record, but: ${problems.join("; ")}.`, record, meter };
  }
  if (!all && !terms.some((t) => /^redirect=/i.test(t))) {
    return { name: "SPF", status: "check", say: "One record, but it has no ending (~all or -all).", fix: "Add ~all at the end.", record, meter };
  }
  if (all && /^\?all$/i.test(all)) {
    return { name: "SPF", status: "check", say: "Ends in ?all, which tells receivers nothing.", fix: "Use ~all or -all.", record, meter };
  }
  if (count >= 8) {
    return { name: "SPF", status: "check", say: `One record, ${count} of 10 lookups used. Close to the limit.`, fix: "Adding one more sending tool could push you over.", record, meter };
  }
  return { name: "SPF", status: "pass", say: `One record, ${count} of 10 lookups used.`, record, meter };
}

async function checkDkim(domain, selector) {
  const list = selector ? [selector] : COMMON_SELECTORS;
  const hits = await Promise.all(list.map(async (sel) => {
    const values = await txt(`${sel}._domainkey.${domain}`).catch(() => []);
    const key = values.find((v) => /(^|;)\s*p=/i.test(v) || /v=DKIM1/i.test(v));
    return key ? { sel, key } : null;
  }));
  const found = hits.filter(Boolean);
  if (!found.length) {
    return selector
      ? { name: "DKIM", status: "fix", say: `No DKIM key at ${selector}._domainkey.${domain}.`, fix: "Check the selector, or turn on DKIM signing in your mail provider and add the record it gives you." }
      : { name: "DKIM", status: "check", say: "No key found under the common selectors.", fix: "Add your selector above (it's the s= value in a sent email's DKIM-Signature) to check it." };
  }
  const revoked = found.filter((f) => /(^|;)\s*p=\s*(;|$)/i.test(f.key));
  const live = found.filter((f) => !revoked.includes(f));
  const record = found.map((f) => `${f.sel}._domainkey  ${f.key.length > 140 ? f.key.slice(0, 140) + "…" : f.key}`).join("\n");
  if (!live.length) {
    return { name: "DKIM", status: "fix", say: "The DKIM key found is empty (revoked).", fix: "Generate a new key in your mail provider and publish it.", record };
  }
  return { name: "DKIM", status: "pass", say: `Key found at selector ${live.map((f) => f.sel).join(", ")}.`, record };
}

function dmarcTags(record) {
  const tags = {};
  for (const part of record.split(";")) {
    const [k, ...v] = part.split("=");
    if (k && v.length) tags[k.trim().toLowerCase()] = v.join("=").trim();
  }
  return tags;
}

async function checkDmarc(domain) {
  let at = domain;
  let recs = (await txt(`_dmarc.${at}`)).filter((t) => /^v=DMARC1/i.test(t));
  // A subdomain without its own record falls back to its parent's policy.
  while (!recs.length && at.split(".").length > 2) {
    at = at.split(".").slice(1).join(".");
    recs = (await txt(`_dmarc.${at}`)).filter((t) => /^v=DMARC1/i.test(t));
  }
  const starter = `v=DMARC1; p=none; rua=mailto:dmarc@${domain}`;
  if (!recs.length) {
    return {
      name: "DMARC", status: "fix",
      say: `No DMARC record at _dmarc.${domain}. Gmail, Yahoo and Outlook require one for bulk senders.`,
      fix: "Add this TXT record at _dmarc to start (it only asks for reports, it blocks nothing):",
      suggest: starter,
    };
  }
  if (recs.length > 1) {
    return { name: "DMARC", status: "fix", say: `${recs.length} DMARC records. Receivers ignore DMARC when there is more than one.`, fix: "Keep one.", record: recs.join("\n") };
  }
  const record = recs[0];
  const tags = dmarcTags(record);
  const p = (tags.p || "").toLowerCase();
  const from = at === domain ? "" : ` (inherited from ${at})`;
  if (!["none", "quarantine", "reject"].includes(p)) {
    return { name: "DMARC", status: "fix", say: `The record has no valid p= policy${from}.`, fix: "Add p=none to start.", record, suggest: starter };
  }
  const reports = tags.rua ? "" : " No rua= address, so you won't get reports.";
  const meaning = {
    none: "p=none: meets the Gmail, Yahoo and Outlook minimum.",
    quarantine: "p=quarantine: failing mail goes to spam.",
    reject: "p=reject: failing mail is refused.",
  }[p];
  return { name: "DMARC", status: "pass", say: `${meaning}${from}${reports}`, record };
}

async function checkSite(domain) {
  const [a, aaaa, cname] = await Promise.all([dns(domain, "A"), dns(domain, "AAAA"), dns(domain, "CNAME")]);
  if (a.answers.length || aaaa.answers.length || cname.answers.length) {
    const addr = [...a.answers, ...aaaa.answers, ...cname.answers].map((x) => x.data.replace(/\.$/, "")).slice(0, 3).join("\n");
    return { name: "Website", status: "pass", say: "The domain points somewhere, so a curious prospect won't hit a dead page.", record: addr };
  }
  return { name: "Website", status: "check", say: "Nothing at the root of this domain.", fix: "Most people forward a sending domain to their main site so it looks real when someone checks." };
}

// ---------- Render ----------

const LABEL = { pass: "Pass", check: "Check", fix: "Fix", pending: "Checking" };

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

function renderRow(row, li) {
  li.className = `check-row s-${row.status}${li.dataset.done ? "" : " arrive"}`;
  li.dataset.done = row.status === "pending" ? "" : "1";
  li.replaceChildren();
  li.append(el("div", "check-name", row.name));
  const body = el("div", "check-body");
  const p = el("p", "say");
  p.append(el("span", "verdict", LABEL[row.status]), document.createTextNode(row.say || ""));
  body.append(p);
  if (row.fix) body.append(el("p", "fix", row.fix));
  if (row.suggest) {
    const box = el("div", "suggest");
    const rec = el("pre", "record", row.suggest);
    const btn = el("button", "ghost", "Copy");
    btn.type = "button";
    btn.addEventListener("click", () => copy(row.suggest, btn));
    box.append(rec, btn);
    body.append(box);
  }
  if (row.meter) {
    const m = el("div", "meter");
    const used = row.meter.used;
    if (used > SPF_LIMIT) m.classList.add("over");
    else if (used >= 8) m.classList.add("near");
    m.setAttribute("role", "img");
    m.setAttribute("aria-label", `${used} of 10 SPF lookups used`);
    for (let i = 0; i < SPF_LIMIT; i++) m.append(el("span", `slot${i < used ? " used" : ""}`));
    body.append(m, el("p", "meter-label", `${used} / 10 lookups`));
  }
  if (row.record) body.append(el("pre", "record", row.record));
  li.append(body);
}

async function copy(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const old = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => { btn.textContent = old; }, 1600);
  } catch {
    btn.textContent = "Copy failed";
  }
}

function setHeadline(domain, rows) {
  const h = $("headline");
  h.replaceChildren();
  const d = el("span", "domain", domain);
  if (!rows) {
    h.append(d, document.createTextNode(" is being checked"));
    return;
  }
  const core = rows.filter((r) => ["MX", "SPF", "DKIM", "DMARC"].includes(r.name));
  const fixes = rows.filter((r) => r.status === "fix").length;
  const checks = rows.filter((r) => r.status === "check").length;
  if (core.every((r) => r.status === "pass")) {
    h.append(d, document.createTextNode(checks ? ` is ready to warm, with ${checks === 1 ? "one thing" : checks + " things"} to look at` : " is ready to warm"));
  } else if (fixes) {
    h.append(d, document.createTextNode(` has ${fixes === 1 ? "one thing" : fixes + " things"} to fix`));
  } else {
    h.append(d, document.createTextNode(` needs ${checks === 1 ? "one thing" : checks + " things"} checked`));
  }
}

async function run(domain, selector) {
  $("error").hidden = true;
  $("go").disabled = true;
  $("results").hidden = false;
  $("share").hidden = true;
  $("lede").hidden = true;
  setHeadline(domain, null);
  cache.clear();

  const jobs = [
    ["MX", () => checkMx(domain)],
    ["SPF", () => checkSpf(domain)],
    ["DKIM", () => checkDkim(domain, selector)],
    ["DMARC", () => checkDmarc(domain)],
    ["Website", () => checkSite(domain)],
  ];
  const list = $("checks");
  list.replaceChildren();
  const rows = await Promise.all(jobs.map(async ([name, fn]) => {
    const li = el("li");
    list.append(li);
    renderRow({ name, status: "pending", say: "" }, li);
    let row;
    try {
      row = await fn();
    } catch {
      row = { name, status: "check", say: "Couldn't reach public DNS for this check. Try again in a moment." };
    }
    renderRow(row, li);
    return row;
  }));

  setHeadline(domain, rows);
  document.title = `${domain}: sending domain check`;
  $("go").disabled = false;
  $("share").hidden = false;
}

function start(e) {
  if (e) e.preventDefault();
  const domain = cleanDomain($("domain").value);
  const selector = ($("selector").value || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "");
  if (!domain) {
    const err = $("error");
    err.textContent = "Enter a domain like getacme.com (no https:// needed).";
    err.hidden = false;
    $("domain").focus();
    return;
  }
  $("domain").value = domain;
  const params = new URLSearchParams({ d: domain });
  if (selector) params.set("s", selector);
  history.replaceState(null, "", `?${params}`);
  run(domain, selector);
}

$("form").addEventListener("submit", start);
$("copy-link").addEventListener("click", (e) => copy(location.href, e.currentTarget));

const params = new URLSearchParams(location.search);
if (params.get("d")) {
  $("domain").value = params.get("d");
  if (params.get("s")) {
    $("selector").value = params.get("s");
    document.querySelector(".selector").open = true;
  }
  start();
}
