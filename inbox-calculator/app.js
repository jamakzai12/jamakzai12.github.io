// Cold email inbox calculator. Pure maths in the browser; nothing is sent anywhere.
"use strict";

const DOMAIN_PRICE = 11.08; // .com a year, what we paid in September 2026
const WARMUP_DAYS = 21;     // up to three weeks of warm-up before the first send

const $ = (id) => document.getElementById(id);
const num = (id, min, fallback) => {
  const v = Math.floor(Number($(id).value));
  return Number.isFinite(v) && v >= min ? v : fallback;
};

function plan(rate, inp) {
  const daily = Math.ceil(inp.weekly / inp.days);
  const sending = Math.ceil(daily / rate);
  const spares = Math.ceil(sending * inp.spare / 100);
  const total = sending + spares;
  const domains = Math.ceil(total / inp.perDomain);
  return { daily, sending, spares, total, domains, sendsPerInbox: rate * inp.steps, cost: domains * DOMAIN_PRICE };
}

function fmtDate(d) {
  return d.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short", year: "numeric" });
}

function render() {
  const inp = {
    weekly: num("weekly", 1, 1000),
    steps: num("steps", 1, 3),
    days: Math.min(num("days", 1, 5), 7),
    perDomain: num("perdomain", 1, 3),
    spare: num("spare", 0, 50),
  };
  const a = plan(num("rate-a", 1, 5), inp);
  const b = plan(num("rate-b", 1, 20), inp);

  let launch = $("launch").valueAsDate;
  if (!launch) {
    launch = new Date();
    launch.setDate(launch.getDate() + WARMUP_DAYS);
    $("launch").valueAsDate = launch;
  }
  const warm = new Date(launch);
  warm.setDate(warm.getDate() - WARMUP_DAYS);
  const late = warm < new Date(new Date().toDateString());

  const rows = [
    ["New contacts a day", a.daily, b.daily, ""],
    ["Sending inboxes", a.sending, b.sending, ""],
    ["Spare inboxes warming", a.spares, b.spares, `${inp.spare}% on top`],
    ["Total inboxes", a.total, b.total, "", "total"],
    ["Domains", a.domains, b.domains, `${inp.perDomain} inboxes each`],
    ["Emails per inbox a day", a.sendsPerInbox, b.sendsPerInbox, "with follow-ups"],
    ["Domain cost a year", `$${Math.round(a.cost)}`, `$${Math.round(b.cost)}`, "at $11.08 each"],
  ];
  $("rows").replaceChildren(...rows.map(([what, va, vb, sub, cls]) => {
    const row = document.createElement("div");
    row.className = `plan-row${cls ? " " + cls : ""}`;
    const w = document.createElement("span");
    w.className = "what";
    w.textContent = what;
    if (sub) { const s = document.createElement("span"); s.className = "sub"; s.textContent = sub; w.append(s); }
    const x = document.createElement("span"); x.className = "val"; x.textContent = Number.isFinite(va) ? va.toLocaleString("en-GB") : va;
    const y = document.createElement("span"); y.className = "val"; y.textContent = Number.isFinite(vb) ? vb.toLocaleString("en-GB") : vb;
    row.append(w, x, y);
    return row;
  }));

  $("headline").textContent = a.total === b.total
    ? `You need ${a.total} inboxes`
    : `You need ${b.total} inboxes. Or ${a.total}.`;
  $("gap").textContent = `Start warming them by ${fmtDate(warm)} to send on ${fmtDate(launch)}.` +
    (late ? " That date has passed, so push the send date back or use pre-warmed inboxes." : "") +
    (a.total !== b.total ? ` Quote the job at ${b.total} and it might need ${a.total}.` : "");
}

document.querySelectorAll("input").forEach((el) => el.addEventListener("input", render));
render();
