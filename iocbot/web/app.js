/* IOC Intel command center (vanilla JS, talks to /api/v1 with an API key) */
"use strict";

const state = {
  key: localStorage.getItem("ioc_key") || "",
  q: "", activeView: "all", sev: new Set(), folder: null,
  since: "", unreviewed: false,
  sort: "last_seen", order: "desc", limit: 50, offset: 0,
  total: 0, selectedSet: new Map(), selected: null, page: "iocs",
  folders: [], timer: null, runTimer: null,
  keysShowRevoked: false, reveal: {},
  hideCols: JSON.parse(localStorage.getItem("ioc_hide_cols") || "[]"),
};

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g,
  (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const selKey = (r) => `${r.ioc_type}|${r.ioc}`;

function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject) => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); }
    catch (e) { ok = false; }
    ta.remove();
    ok ? resolve() : reject(new Error("copy not supported"));
  });
}

function toast(msg, err) {
  const el = $("toast");
  el.textContent = msg;
  el.className = "toast" + (err ? " err" : "");
  el.classList.remove("hidden");
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.add("hidden"), err ? 5000 : 2500);
}

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (state.key) headers["X-API-Key"] = state.key;
  let body = opts.body;
  if (body !== undefined && typeof body !== "string") {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(body);
  }
  const res = await fetch("/api/v1" + path, Object.assign({}, opts, { headers, body }));
  if (res.status === 401) { showLogin(); throw new Error("API key required"); }
  const ct = res.headers.get("content-type") || "";
  if (!res.ok) {
    let detail = res.statusText;
    if (ct.includes("json")) {
      const j = await res.json().catch(() => ({}));
      detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail || j);
    }
    throw new Error(detail);
  }
  return ct.includes("json") ? res.json() : res;
}

function showLogin(msg) {
  $("login").classList.remove("hidden");
  $("login-error").textContent = msg || "";
  setConn("err", "disconnected");
  refreshLoginMode();
}
function hideLogin() { $("login").classList.add("hidden"); }

/* Role options offered at sign-up. "admin" is intentionally absent: it must be
   granted by an existing admin, never self-assigned. */
const ROLE_OPTIONS = [
  { value: "viewer", label: "Viewer — can search, view and export IOCs",
    help: "Read-only. Good for analysts who mainly review and triage indicators." },
  { value: "analyst", label: "Analyst — can also create, edit and delete IOCs",
    help: "Read and write. Use if you need to curate, correct or remove indicators." },
];

function populateRoleSelect() {
  const sel = $("reg-role");
  if (!sel) return;
  sel.innerHTML = ROLE_OPTIONS
    .map((r) => `<option value="${r.value}">${esc(r.label)}</option>`).join("");
  updateRoleHelp();
  sel.onchange = updateRoleHelp;
}
function updateRoleHelp() {
  const sel = $("reg-role");
  const opt = ROLE_OPTIONS.find((r) => r.value === sel.value);
  $("reg-role-help").textContent = opt ? opt.help : "";
}

/* Decide between first-run provisioning, sign-in, and registration. */
async function refreshLoginMode() {
  try {
    const res = await fetch("/api/v1/auth/status");
    const st = await res.json();
    const firstRun = Boolean(st.auth_required) && !st.has_users;
    $("login-provision").classList.toggle("hidden", !firstRun);
    $("login-signin").classList.toggle("hidden", firstRun);
    // Registration is offered once an admin exists and the admin hasn't closed it.
    const canRegister = Boolean(st.auth_required) && !firstRun && st.allow_registration !== false;
    $("login-register-toggle").classList.toggle("hidden", firstRun || st.allow_registration === false);
    if (canRegister) populateRoleSelect();
  } catch (e) { /* keep whatever is on screen */ }
}
function setConn(stateName, label) {
  $("conn-state").textContent = label;
  $("conn-dot").className = "dot";
  if (stateName === "ok") $("conn-dot").classList.add("ok");
  else if (stateName === "err") $("conn-dot").classList.add("err");
}

/* keep the sticky KPI strip / sidebar offsets aligned with the real header
   height, otherwise the sidebar's first rows end up under the KPI strip */
function syncStickyOffsets() {
  const header = document.querySelector("header");
  const kpi = document.querySelector(".kpi-strip");
  if (!header || !kpi) return;
  const h = header.offsetHeight;
  const root = document.documentElement.style;
  root.setProperty("--header-h", h + "px");
  root.setProperty("--chrome-h", h + kpi.offsetHeight + "px");
}

function download(path, filename) {
  const sep = path.includes("?") ? "&" : "?";
  window.open(`/api/v1${path}${sep}apikey=${encodeURIComponent(state.key)}`, "_blank");
}

/* ================= views / nav ================= */
const VIEWS = {
  all:       { title: "All IOCs", desc: "Every indicator currently in the intelligence base.",
               meta: n => `${n} indicators` },
  recent:    { title: "Recently Added", desc: "Indicators first seen or updated today.",
               meta: n => `${n} indicators` },
  critical:  { title: "Critical", desc: "Indicators scored CRITICAL severity — treat as highest priority.",
               meta: n => `${n} critical indicators` },
  importable:{ title: "SIEM-Importable", desc: "Validated indicators ready for CrowdStrike / SIEM ingestion.",
               meta: n => `${n} importable indicators` },
  review:    { title: "Needs Review", desc: "Indicators without validation — triage and confirm before use.",
               meta: n => `${n} indicators` },
  c2:        { title: "C2 Infrastructure", desc: "Command-and-control endpoints and staging infra.",
               meta: n => `${n} C2 indicators` },
  malware:   { title: "Malware Distribution", desc: "Malware delivery and distribution indicators.",
               meta: n => `${n} indicators` },
};

function filters() {
  const p = new URLSearchParams();
  if (state.q) p.set("q", state.q);
  if (state.activeView === "importable") p.set("view", "importable");
  if (state.activeView === "c2") p.set("view", "c2");
  if (state.activeView === "malware") p.set("view", "malware");
  if (state.activeView === "recent") p.set("since", new Date().toISOString().slice(0, 10));
  if (state.activeView === "review") p.set("unreviewed", "true");
  const sev = new Set(state.sev);
  if (state.activeView === "critical") sev.add("CRITICAL");
  if (sev.size) p.set("severity", [...sev].join(","));
  if (state.folder) p.set("folder_id", state.folder.id);
  p.set("sort", state.sort);
  p.set("order", state.order);
  p.set("limit", state.limit);
  p.set("offset", state.offset);
  return p;
}

function setActiveView(view) {
  state.activeView = view;
  state.offset = 0;
  renderNav(); renderBreadcrumb(); loadRows();
}

function renderNav() {
  document.querySelectorAll("#side-nav .nav[data-view]").forEach((li) => {
    li.classList.toggle("on", li.dataset.view === state.activeView);
  });
}

function renderBreadcrumb() {
  const view = VIEWS[state.activeView] || VIEWS.all;
  const crumbs = $("breadcrumb");
  crumbs.innerHTML = `Intelligence <span>/</span>` +
    (state.folder
      ? `<span class="here">${esc(state.folder.group)}</span><span>/</span><span class="here">${esc(state.folder.name)}</span>`
      : `<span class="here">${esc(view.title)}</span>`);
  $("page-title").textContent = state.folder ? state.folder.name : view.title;
  $("page-desc").textContent = state.folder
    ? (state.folder.description || `${state.folder.name} — ${state.folder.kind === "auto" ? "auto-generated folder" : "manual folder"}`)
    : view.desc;
  $("page-meta").textContent = `${view.meta(state.total)} · updated ${state.lastCycle || "—"}`;
}

/* ================= data loading ================= */
async function loadStats() {
  try {
    const s = await api("/stats");
    state.lastCycle = s.last_cycle && s.last_cycle.finished ? s.last_cycle.finished : "—";
    const sev = s.by_severity || {};
    $("k-v-total").textContent = s.total.toLocaleString();
    $("k-v-critical").textContent = (sev.CRITICAL || 0).toLocaleString();
    $("k-v-high").textContent = (sev.HIGH || 0).toLocaleString();
    $("k-v-importable").textContent = s.importable.toLocaleString();
    $("k-v-new").textContent = s.new_today.toLocaleString();
    $("svc-all").textContent = s.total.toLocaleString();
    $("svc-recent").textContent = s.new_today.toLocaleString();
    $("svc-critical").textContent = (sev.CRITICAL || 0).toLocaleString();
    $("svc-importable").textContent = s.importable.toLocaleString();
    $("svc-c2").textContent = (s.c2 || 0).toLocaleString();
    $("svc-malware").textContent = (s.malware || 0).toLocaleString();
    // "Needs Review" is a work queue: hide it entirely when there is nothing
    // to review, rather than offering a view that can only ever be empty.
    const unreviewed = s.unreviewed || 0;
    $("svc-review").textContent = unreviewed.toLocaleString();
    $("sv-review").classList.toggle("hidden", unreviewed === 0);
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"].forEach((k) => {
      const b = $(`sc-${k}`);
      if (b) b.textContent = (sev[k] || 0).toLocaleString();
    });
    $("last-run").textContent = s.last_cycle && s.last_cycle.id
      ? `last cycle #${s.last_cycle.id} · ${s.last_cycle.finished || s.last_cycle.started}`
      : "no cycle yet";
    setConn("ok", "connected");
    return s;
  } catch (e) { setConn("err", "error"); throw e; }
}

async function loadFolders() {
  const res = await api("/folders?include_zero=false");
  state.folders = res.items;
  renderFolders();
  const opts = res.items.map((f) => `<option value="${f.id}">${esc(f.name)}</option>`).join("");
  $("d-folder-add").innerHTML = `<option value="">— add to folder —</option>` + opts;
  $("bulk-folder").innerHTML = `<option value="">Add to folder…</option>` + opts;
}

function renderFolders() {
  const term = ($("folder-search").value || "").toLowerCase();
  const list = state.folders.filter((f) => f.name.toLowerCase().includes(term));
  $("folder-count").textContent = `(${state.folders.length})`;
  const groups = [
    ["malware", "Malware groups"],
    ["actor", "Threat actors"],
    ["manual", "My folders"],
  ];
  let html = `<div class="folder ${state.folder && !state.folder.kind ? "on" : ""}" data-id="" data-kind="all">
      <span class="n">All IOCs</span><span class="c"></span></div>`;
  for (const [g, label] of groups) {
    const items = list.filter((f) => f.group === g);
    if (!items.length) continue;
    html += `<div class="folder group-label">${label}</div>`;
    html += items.slice(0, 400).map((f) => `
      <div class="folder ${state.folder && state.folder.id === f.id ? "on" : ""}" data-id="${f.id}"
           title="${esc(f.description || f.name)}">
        <span class="n">${esc(f.name)}</span><span class="c">${f.count.toLocaleString()}</span>
      </div>`).join("");
    if (items.length > 400) html += `<div class="folder more-label">… ${items.length - 400} more</div>`;
  }
  $("folders").innerHTML = html;
  $("folders").querySelectorAll(".folder[data-id]").forEach((el) => {
    el.onclick = (e) => {
      e.stopPropagation();
      const id = el.dataset.id;
      if (id === "") {
        state.folder = null;
      } else {
        state.folder = state.folders.find((f) => String(f.id) === id) || null;
      }
      state.offset = 0;
      renderFolders(); renderBreadcrumb(); loadRows();
    };
  });
}

function clearAllFilters() {
  state.q = ""; $("search").value = "";
  state.activeView = "all";
  state.sev.clear();
  state.folder = null;
  state.unreviewed = false;
  state.since = "";
  state.offset = 0;
  renderNav(); syncSevChips(); renderFolders();
  loadRows(); renderActiveFilters();
}

/* Tell the user WHY the table is empty and give them a way out. */
function emptyRowsHtml(message) {
  const active = state.q || state.activeView !== "all" || state.sev.size ||
                 state.folder || state.unreviewed || state.since;
  const why = active
    ? "<p>Nothing matches the filters currently applied.</p>" +
      "<p class=\"muted small\">Try broadening the search, clearing a severity filter, or selecting All IOCs.</p>"
    : `<p>${message}</p>`;
  const action = active
    ? `<button class="ghost" id="empty-clear">Clear all filters</button>`
    : "";
  return `<tr><td colspan="10" class="empty">
    <div class="empty-inner">${why}${action}</div></td></tr>`;
}

function wireEmptyActions() {
  const btn = $("empty-clear");
  if (btn) btn.onclick = clearAllFilters;
}

function skeletonRows() {
  const cells = Array.from({ length: 8 }, (_, i) =>
    `<td><span class="sk sk-${i}"></span></td>`).join("");
  return Array.from({ length: 6 }, () => `<tr class="sk-row"><td class="col-sel"></td>${cells}</tr>`).join("");
}

async function loadRows() {
  const rowsEl = $("rows");
  rowsEl.innerHTML = skeletonRows();
  try {
    const res = await api(`/iocs?${filters().toString()}`);
    state.total = res.total;
    $("result-count").textContent = `${res.total.toLocaleString()} matching`;
    const from = res.total ? state.offset + 1 : 0;
    const to = Math.min(state.offset + res.limit, res.total);
    $("page-info").textContent = `${from}–${to} of ${res.total.toLocaleString()}`;
    $("prev").disabled = state.offset === 0;
    $("next").disabled = to >= res.total;
    if (!res.items.length) {
      const msg = state.activeView === "review"
        ? "<p>Every indicator in the database has a validation verdict.</p>" +
          "<p class=\"muted small\">Nothing is waiting for review right now.</p>"
        : "<p>No indicators have been collected yet.</p>" +
          "<p class=\"muted small\">Run a collection cycle to populate the intelligence base.</p>";
      rowsEl.innerHTML = emptyRowsHtml(msg);
      wireEmptyActions();
      $("summary").innerHTML = "";
      $("context").innerHTML = "";
    } else {
      rowsEl.innerHTML = res.items.map(rowHtml).join("");
      rowsEl.querySelectorAll("tr.r-ioc").forEach((tr) => {
        tr.onclick = (e) => {
          if (e.target.closest("input,button,.entity,.kebab-wrap")) return;
          openDrawer(tr.dataset.type, decodeURIComponent(tr.dataset.ioc));
        };
      });
      rowsEl.querySelectorAll("input.cb").forEach((cb) => {
        cb.onclick = (e) => {
          e.stopPropagation();
          toggleSel(cb.value);
          syncHeaderCheck();
        };
      });
      rowsEl.querySelectorAll(".kebab-btn").forEach((b) => {
        b.onclick = (e) => { e.stopPropagation(); openRowMenu(b); };
      });
      rowsEl.querySelectorAll(".entity[data-fam]").forEach((e) => {
        e.onclick = (ev) => { ev.stopPropagation(); state.q = e.dataset.fam; $("search").value = e.dataset.fam; state.offset = 0; loadRows(); renderActiveFilters(); };
      });
      renderSummary(res.items, res.total);
      renderContext(res.items);
    }
    renderActiveFilters(); renderSortMarks();
  } catch (e) {
    rowsEl.innerHTML = `<tr><td colspan="10" class="empty error">${esc(e.message)}</td></tr>`;
  }
  syncHeaderCheck();
  renderBreadcrumb();
}

/* --- table row --- */
const CONF_STYLE = { CRITICAL: ["c", "c", "c", "c"], HIGH: ["h", "h", "h", "f"], MEDIUM: ["m", "m", "f", "f"], LOW: ["l", "f", "f", "f"] };
function confCell(conf) {
  const segs = CONF_STYLE[conf] || ["f", "f", "f", "f"];
  const bar = segs.map((s) => `<span class="seg ${s}"></span>`).join("");
  return `<span class="conf"><span class="conf-bar">${bar}</span><span class="conf-lbl">${esc(conf || "—")}</span></span>`;
}
function catsCell(r) {
  const cats = (r.categories || []).slice(0, 3).map((c) => `<span class="tag">${esc(c)}</span>`).join("");
  return (cats || '<span class="muted">—</span>') +
    (r.categories.length > 3 ? `<span class="tag">+${r.categories.length - 3}</span>` : "");
}
function entitiesCell(r) {
  const fam = r.malware_family ? `<span class="entity fam" data-fam="${esc(r.malware_family)}" title="Search ${esc(r.malware_family)}">${esc(r.malware_family)}</span>` : "";
  const act = r.threat_actor ? `<span class="entity act" data-fam="${esc(r.threat_actor)}" title="Search ${esc(r.threat_actor)}">${esc(r.threat_actor)}</span>` : "";
  return fam + act || '<span class="muted">—</span>';
}
function rowHtml(r, i) {
  const key = selKey(r);
  const checked = state.selectedSet.has(key) ? " checked" : "";
  const folders = (r.folders || []).map((f) => `<span class="tag">${esc(f)}</span>`).join("");
  return `<tr class="r-ioc ${checked && "checked"}" data-ioc="${encodeURIComponent(r.ioc)}" data-type="${esc(r.ioc_type)}">
    <td class="col-sel" data-col="sel"><input type="checkbox" class="cb" value="${escapeAttr(key)}" ${checked}></td>
    <td data-col="ioc"><span class="ioc-val">${esc(r.ioc)}</span></td>
    <td data-col="ioc_type"><span class="tag">${esc(r.ioc_type)}</span></td>
    <td data-col="severity"><span class="badge b-${esc(r.severity || "EMPTY")}">${esc(r.severity || "—")}</span></td>
    <td data-col="confidence">${confCell(r.confidence)}</td>
    <td data-col="category">${catsCell(r)}</td>
    <td data-col="malware">${entitiesCell(r)}</td>
    <td data-col="folders">${folders || '<span class="muted">—</span>'}</td>
    <td data-col="last_seen" class="muted small nowrap mono">${esc(r.last_seen || "—")}</td>
    <td class="col-actions" data-col="actions"><span class="kebab-wrap"><button class="kebab-btn" title="Actions">⋯</button></span></td>
  </tr>`;
}

/* --- bulk selection --- */
function toggleSel(key) {
  state.selectedSet.has(key) ? state.selectedSet.delete(key) : state.selectedSet.set(key, true);
  updateBulk();
}
function updateBulk() {
  const bar = $("bulk-bar");
  const n = state.selectedSet.size;
  bar.classList.toggle("hidden", n === 0);
  $("bulk-count").textContent = n;
}
function syncHeaderCheck() {
  const cbs = [...document.querySelectorAll("#rows .cb")];
  const all = cbs.every((c) => c.checked);
  const some = cbs.some((c) => c.checked);
  const h = $("check-all");
  h.checked = all && cbs.length > 0;
  h.indeterminate = some && !all;
}
async function bulkDelete() {
  if (!state.selectedSet.size) return;
  if (!confirm(`Delete ${state.selectedSet.size} selected IOC(s)? This cannot be undone.`)) return;
  let failed = 0;
  for (const key of state.selectedSet.keys()) {
    const [type, ioc] = key.split("|");
    try { await api(`/iocs/${encodeURIComponent(type)}/${encodeURIComponent(ioc)}`, { method: "DELETE" }); }
    catch (e) { failed++; }
  }
  state.selectedSet = new Map();
  updateBulk();
  loadRows(); loadStats(); loadFolders();
  toast(failed ? `deleted, ${failed} failed` : "deleted");
}
async function bulkApply() {
  const id = $("bulk-folder").value;
  if (!id || !state.selectedSet.size) return;
  const iocs = [...state.selectedSet.keys()].map((k) => {
    const [type, ioc] = k.split("|");
    return { ioc_type: type, ioc };
  });
  try {
    const r = await api(`/folders/${id}/iocs`, { method: "POST", body: { iocs } });
    toast(r ? `added to folder (${iocs.length})` : "added");
    loadFolders(); loadRows();
  } catch (e) { toast(e.message, true); }
}

/* --- summary strip + context panel --- */
function renderSummary(items, total) {
  const cutoff = total > items.length;
  const plus = () => (cutoff ? "·+" : "");
  let crit = 0, high = 0, doms = 0, cves = 0, last = "";
  for (const it of items) {
    if (it.severity === "CRITICAL") crit++;
    if (it.severity === "HIGH") high++;
    if (it.ioc_type === "Domain") doms++;
    if (it.ioc_type === "CVE") cves++;
    if (it.last_seen > last) last = it.last_seen;
  }
  $("summary").innerHTML = `
    <div class="sum-card"><div class="sum-val">${total.toLocaleString()}</div><div class="sum-lbl">Indicators in view</div></div>
    <div class="sum-card"><div class="sum-val crit">${(crit + high).toLocaleString()}${plus()}</div><div class="sum-lbl">Critical / High</div></div>
    <div class="sum-card"><div class="sum-val">${doms.toLocaleString()}${plus()}</div><div class="sum-lbl">Domains</div></div>
    <div class="sum-card"><div class="sum-val">${cves.toLocaleString()}${plus()}</div><div class="sum-lbl">CVEs</div></div>
    <div class="sum-card"><div class="sum-val">${esc(last ? last.slice(0, 10) : "—")}</div><div class="sum-lbl">Last observed</div></div>`;
}

function tally(items) {
  const t = { actor: {}, fam: {}, cat: {}, cve: [], type: {}, conf: {} };
  for (const it of items) {
    if (it.threat_actor) t.actor[it.threat_actor] = (t.actor[it.threat_actor] || 0) + 1;
    if (it.malware_family) t.fam[it.malware_family] = (t.fam[it.malware_family] || 0) + 1;
    (it.categories || []).forEach((c) => { t.cat[c] = (t.cat[c] || 0) + 1; });
    if (it.ioc_type === "CVE") t.cve.push(it.ioc);
    t.type[it.ioc_type] = (t.type[it.ioc_type] || 0) + 1;
    t.conf[it.confidence || "LOW"] = (t.conf[it.confidence || "LOW"] || 0) + 1;
  }
  return t;
}
const ttop = (o, n = 6) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n);
const CONF_COLORS = { CRITICAL: "var(--crit)", HIGH: "var(--high)", MEDIUM: "var(--med)", LOW: "var(--low)" };
function renderContext(items) {
  const t = tally(items);
  const n = items.length;
  const confTotal = Object.values(t.conf).reduce((a, b) => a + b, 0) || 1;
  const bar = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((k) => {
    const v = t.conf[k] || 0;
    return v ? `<i style="flex:${v};background:${CONF_COLORS[k]}" title="${k}: {{v}}"></i>`.replace("{{v}}", v) : "";
  }).join("");
  const legend = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((k) =>
    `<span><span class="sw" style="background:${CONF_COLORS[k]}"></span>${k} ${(t.conf[k] || 0)}</span>`).join("");
  const chips = (o) => ttop(o).map(([k, v]) =>
    `<span class="ctx-chip">${esc(k)} <b>${v}</b></span>`).join("") || '<span class="muted small">none on this page</span>';
  const cards = [];
  cards.push(`<div class="ctx-card"><h4>Threat actors</h4><div class="row">${chips(t.actor)}</div></div>`);
  cards.push(`<div class="ctx-card"><h4>Malware families</h4><div class="row">${chips(t.fam)}</div></div>`);
  cards.push(`<div class="ctx-card"><h4>Categories</h4><div class="row">${chips(t.cat)}</div></div>`);
  cards.push(`<div class="ctx-card"><h4>Confidence mix</h4><div class="bar">${bar}</div><div class="legend">${legend}</div></div>`);
  cards.push(`<div class="ctx-card"><h4>Indicator types</h4><div class="row">${chips(t.type)}</div></div>`);
  cards.push(`<div class="ctx-card"><h4>Observed CVEs</h4><div class="row">${t.cve.slice(0, 6).map((c) => `<span class="tag mono">${esc(c)}</span>`).join("") || '<span class="muted small">none on this page</span>'}</div></div>`);
  $("context").innerHTML =
    `<div class="ctx-h">Threat context · ${n} indicators on this page</div><div class="ctx-grid">${cards.join("")}</div>`;
}

/* --- filters chips --- */
function renderActiveFilters() {
  const chips = [];
  if (state.q) chips.push(["q", `search: ${state.q}`]);
  if (state.activeView !== "all") chips.push(["view", `view: ${VIEWS[state.activeView].title}`]);
  if (state.sev.size) chips.push(["sev", `severity: ${[...state.sev].join(",")}`]);
  if (state.folder) chips.push(["folder", `folder: ${state.folder.name}`]);
  if (state.unreviewed) chips.push(["unrev", "needs review"]);
  // One-click escape hatch when more than one filter is stacked up.
  const clearAll = chips.length > 1
    ? `<button class="chip clear-all" id="clear-all" title="Remove every filter">clear all ✕</button>`
    : "";
  $("active-filters").innerHTML = chips.map(([k, label]) =>
    `<button class="chip on" data-k="${k}" title="Remove this filter">${esc(label)} ✕</button>`).join("") + clearAll;
  const ca = $("clear-all");
  if (ca) ca.onclick = clearAllFilters;
  $("active-filters").querySelectorAll(".chip[data-k]").forEach((c) => {
    c.onclick = () => {
      const k = c.dataset.k;
      if (k === "q") { state.q = ""; $("search").value = ""; }
      if (k === "view") { state.activeView = "all"; renderNav(); }
      if (k === "sev") { state.sev.clear(); syncSevChips(); }
      if (k === "folder") { state.folder = null; renderFolders(); }
      if (k === "unrev") { state.unreviewed = false; }
      state.offset = 0; loadRows(); renderActiveFilters();
    };
  });
}

function syncSevChips() {
  document.querySelectorAll("#severity-chips .chip").forEach((c) =>
    c.classList.toggle("on", state.sev.has(c.dataset.sev)));
}
function renderSortMarks() {
  const sortCol = state.sort === "malware_family" ? "malware" : state.sort;
  document.querySelectorAll("thead th[data-sort]").forEach((th) => {
    th.classList.toggle("sort-desc", th.dataset.sort === sortCol && state.order === "desc");
    th.classList.toggle("sort-asc", th.dataset.sort === sortCol && state.order === "asc");
  });
}

/* ================= drawer / CRUD ================= */
async function openDrawer(type, ioc) {
  try {
    const item = await api(`/iocs/${encodeURIComponent(type)}/${encodeURIComponent(ioc)}`);
    state.selected = item;
    $("d-title").textContent = item.ioc_type + " · " + item.ioc;
    $("d-ioc").textContent = item.ioc;
    $("d-type").textContent = item.ioc_type;
    $("d-val").textContent = item.validation_status || "—";
    $("d-severity").value = item.severity || "LOW";
    $("d-confidence").value = item.confidence || "LOW";
    $("d-categories").value = (item.categories || []).join("; ");
    $("d-family").value = item.malware_family || "";
    $("d-actor").value = item.threat_actor || "";
    $("d-campaign").value = item.campaign || "";
    $("d-desc").value = item.description || "";
    $("d-tags").value = (item.tags || []).join("; ");
    $("d-first").textContent = item.first_seen || "—";
    $("d-last").textContent = item.last_seen || "—";
    $("d-imp").textContent = item.crowdstrike_importable || "NO";
    $("d-sources").textContent = (item.sources || []).join(" | ") || "—";
    $("d-folders").innerHTML = (item.folders || []).length
      ? item.folders.map((f) => `<span class="tag on">${esc(f)}</span>`).join("")
      : '<span class="muted small">none</span>';
    document.querySelectorAll("#rows tr").forEach((tr) => tr.classList.remove("sel"));
    const sel = [...document.querySelectorAll("#rows tr.r-ioc")]
      .find((tr) => tr.dataset.type === item.ioc_type && decodeURIComponent(tr.dataset.ioc) === item.ioc);
    if (sel) sel.classList.add("sel");
    $("drawer").classList.remove("hidden");
  } catch (e) { toast(e.message, true); }
}

async function saveDrawer() {
  if (!state.selected) return;
  const body = {
    severity: $("d-severity").value,
    confidence: $("d-confidence").value,
    categories: $("d-categories").value.split(";").map((s) => s.trim()).filter(Boolean),
    malware_family: $("d-family").value.trim(),
    threat_actor: $("d-actor").value.trim(),
    campaign: $("d-campaign").value.trim(),
    description: $("d-desc").value,
    tags: $("d-tags").value.split(";").map((s) => s.trim()).filter(Boolean),
  };
  try {
    await api(`/iocs/${encodeURIComponent(state.selected.ioc_type)}/${encodeURIComponent(state.selected.ioc)}`,
      { method: "PUT", body });
    toast("saved");
    loadRows(); loadStats(); loadFolders();
    openDrawer(state.selected.ioc_type, state.selected.ioc);
  } catch (e) { toast(e.message, true); }
}

async function deleteDrawer() {
  if (!state.selected) return;
  if (!confirm(`Delete ${state.selected.ioc_type} ${state.selected.ioc}?`)) return;
  try {
    await api(`/iocs/${encodeURIComponent(state.selected.ioc_type)}/${encodeURIComponent(state.selected.ioc)}`,
      { method: "DELETE" });
    toast("deleted");
    $("drawer").classList.add("hidden");
    state.selected = null;
    loadRows(); loadStats(); loadFolders();
  } catch (e) { toast(e.message, true); }
}

async function addToFolder() {
  const id = $("d-folder-add").value;
  if (!id || !state.selected) return;
  try {
    await api(`/folders/${id}/iocs`, { method: "POST", body: {
      iocs: [{ ioc: state.selected.ioc, ioc_type: state.selected.ioc_type }] } });
    toast("added to folder");
    loadRows(); loadFolders();
    openDrawer(state.selected.ioc_type, state.selected.ioc);
  } catch (e) { toast(e.message, true); }
}

/* ================= row kebab menu ================= */
function openRowMenu(btn) {
  const tr = btn.closest("tr");
  const type = tr.dataset.type, ioc = decodeURIComponent(tr.dataset.ioc);
  const menu = $("row-menu");
  const folders = state.folders.map((f) => `<option value="${f.id}">${esc(f.name)}</option>`).join("");
  menu.innerHTML = `
    <button class="pop-item" data-act="view">View / edit</button>
    <button class="pop-item" data-act="copy">Copy value</button>
    <div class="pop-item drop" style="padding:7px 9px 2px;color:var(--faint);font-size:11px">Add to folder</div>
    <select class="pop-select" id="rm-folder">${folders}</select>
    <button class="pop-item" data-act="add">+ Add to selected folder</button>
    <div class="divider" style="margin:4px 0"></div>
    <button class="pop-item danger" data-act="del">Delete IOC</button>`;
  posPopover(menu, btn);
  menu.classList.remove("hidden");
  menu._item = { type, ioc };
  menu.querySelectorAll("[data-act]").forEach((b) => {
    b.onclick = async () => {
      const act = b.dataset.act, it = menu._item;
      if (act === "view") { menu.classList.add("hidden"); openDrawer(it.type, it.ioc); }
      else if (act === "copy") {
        try { await copyText(it.ioc); toast("copied"); }
        catch (e) { toast("copy failed", true); }
        menu.classList.add("hidden");
      }
      else if (act === "add") {
        const fid = menu.querySelector("#rm-folder").value;
        if (!fid) return;
        try {
          await api(`/folders/${fid}/iocs`, { method: "POST", body: { iocs: [{ ioc: it.ioc, ioc_type: it.type }] } });
          toast("added to folder"); loadFolders(); loadRows();
        } catch (e) { toast(e.message, true); }
        menu.classList.add("hidden");
      }
      else if (act === "del") {
        menu.classList.add("hidden");
        if (!confirm(`Delete ${it.type} ${it.ioc}?`)) return;
        try {
          await api(`/iocs/${encodeURIComponent(it.type)}/${encodeURIComponent(it.ioc)}`, { method: "DELETE" });
          toast("deleted"); loadRows(); loadStats(); loadFolders();
        } catch (e) { toast(e.message, true); }
      }
    };
  });
}

function posPopover(el, anchor) {
  const r = anchor.getBoundingClientRect();
  el.style.position = "fixed";
  el.style.left = Math.max(6, r.right - 190) + "px";
  el.style.top = Math.min(window.innerHeight - 80, r.bottom + 4) + "px";
}

/* ================= modals ================= */
function showNewIoc() {
  $("n-error").textContent = "";
  ["n-ioc", "n-family", "n-actor", "n-categories", "n-desc"].forEach((id) => $(id).value = "");
  $("modal-new").classList.remove("hidden");
  $("n-ioc").focus();
}
async function createIoc() {
  const body = {
    ioc: $("n-ioc").value.trim(),
    ioc_type: $("n-type").value,
    severity: $("n-severity").value,
    confidence: $("n-confidence").value,
    categories: $("n-categories").value.split(";").map((s) => s.trim()).filter(Boolean),
    malware_family: $("n-family").value.trim(),
    threat_actor: $("n-actor").value.trim(),
    description: $("n-desc").value,
    force: $("n-force").checked,
  };
  try {
    const created = await api("/iocs", { method: "POST", body });
    $("modal-new").classList.add("hidden");
    toast("IOC created");
    loadRows(); loadStats(); loadFolders();
    openDrawer(created.ioc_type, created.ioc);
  } catch (e) { $("n-error").textContent = e.message; }
}
async function createFolder() {
  $("f-error").textContent = "";
  try {
    const folder = await api("/folders", { method: "POST", body: {
      name: $("f-name").value.trim(), description: $("f-desc").value } });
    $("modal-folder").classList.add("hidden");
    $("f-name").value = ""; $("f-desc").value = "";
    toast(`folder "${folder.name}" created`);
    loadFolders();
  } catch (e) { $("f-error").textContent = e.message; }
}

/* ================= keys ================= */
const PLATFORM_HINTS = {
  "Splunk": "Pull as a scripted input / scheduled search: curl the feed URL below into a CSV data input, or poll it from Dashboards.",
  "Elastic": "Ingest with an HTTP poller (Logstash http_poller / Elastic Agent) pointed at the JSON feed, adding the X-API-Key header.",
  "Wazuh": "Add a command localfile in ossec.conf that curls the CSV feed and lets Wazuh match on the indicator values.",
  "FortiSIEM": "Use the CSV feed with an HTTP reference collection / worker poller; map IOC, SEVERITY, CATEGORY, MALWARE_FAMILY columns.",
  "CrowdStrike": "CrowdStrike needs outbound push (IOC Management / Falcon APIs) rather than pull — use the Push modal and config/push.yaml.",
  "QRadar": "Poll the JSON feed from a custom property / store & collect HTTP source; keep min_severity + importable view for IoC semantics.",
  "Sentinel": "Wire a Logic App / custom connector that calls the JSON or STIX feed with the API key header.",
  "Other": "Point your SIEM at /api/v1/feed (CSV / JSON / STIX) with the X-API-Key header. Full reference: docs/API.md",
};

function platformHint(platform, base) {
  const url = (base || window.location.origin) + "/api/v1/feed";
  const h = PLATFORM_HINTS[platform];
  if (!h) return "";
  return `${h}<br>Example: <code>curl -H "X-API-Key: &lt;key&gt;" "${esc(url)}?format=json&amp;min_severity=HIGH"</code>`;
}

function hideNewKey() { $("k-new-key").innerHTML = ""; $("k-new-key").classList.add("hidden"); }
function showNewKey(label, plain) {
  $("k-new-key").innerHTML = `${esc(label)}<br><code>${esc(plain)}</code>`;
  $("k-new-key").classList.remove("hidden");
}

function keysRow(k) {
  const rev = k.revoked ? ' <span class="muted">(revoked)</span>' : "";
  const last = k.last_used_at ? `${esc(k.last_used_at)} <span class="muted small">(${k.uses} uses)</span>` : "never";
  const ip = k.last_ip ? `<span class="mono small">${esc(k.last_ip)}</span>` : '<span class="muted">—</span>';
  const pf = k.platform ? `<span class="tag">${esc(k.platform)}</span>` : '<span class="muted">—</span>';
  const reveal = state.reveal[k.id]
    ? `<button data-act="reveal" data-id="${k.id}">copy</button> ` : "";
  const actions = k.revoked ? `<span class="muted small">revoked</span>`
    : `${reveal}<button data-act="rotate" data-id="${k.id}">rotate</button> <button data-act="revoke" data-id="${k.id}">revoke</button>`;
  return `<tr><td>${esc(k.name)}${rev}</td>
    <td>${esc(k.scopes.join(","))}</td><td>${pf}</td><td class="mono">${esc(k.prefix)}…</td>
    <td class="muted">${esc(k.created_at || "—")}</td>
    <td>${last}</td><td class="muted">${k.uses}</td><td>${ip}</td>
    <td class="nowrap">${actions}</td></tr>`;
}

async function loadUsers() {
  try {
    const res = await api("/users");
    // Only admins can list users; non-admins just don't see the card.
    const users = res.users || [];
    const card = $("users-card");
    card.classList.toggle("hidden", false);
    $("users-rows").innerHTML = users.map((u) => {
      const badge = `<span class="tag role-${esc(u.role)}">${esc(u.role)}</span>`;
      const status = u.disabled ? `<span class="muted">disabled</span>`
                                : `<span class="ok">active</span>`;
      const sel = `<select class="role-sel" data-id="${u.id}">
        <option value="viewer"${u.role === "viewer" ? " selected" : ""}>Viewer</option>
        <option value="analyst"${u.role === "analyst" ? " selected" : ""}>Analyst</option>
        <option value="admin"${u.role === "admin" ? " selected" : ""}>Admin</option>
      </select>`;
      const toggle = `<button class="ghost small" data-act="toggle" data-id="${u.id}">
        ${u.disabled ? "Enable" : "Disable"}</button>`;
      return `<tr>
        <td><strong>${esc(u.username)}</strong>${u.full_name ? ` <span class="muted small">${esc(u.full_name)}</span>` : ""}</td>
        <td>${badge}</td><td>${status}</td>
        <td class="muted small">${esc((u.created_at || "").slice(0, 10))}</td>
        <td class="muted small">${esc((u.last_login_at || "never").slice(0, 16))}</td>
        <td class="nowrap">${sel} ${toggle}</td></tr>`;
    }).join("");
    $("users-rows").querySelectorAll(".role-sel").forEach((s) => {
      s.onchange = async () => {
        try {
          await api(`/users/${s.dataset.id}/role`, { method: "PUT", body: { role: s.value } });
          toast("role updated"); loadUsers();
        } catch (err) { $("u-error").textContent = err.message; loadUsers(); }
      };
    });
    $("users-rows").querySelectorAll("button[data-act=toggle]").forEach((b) => {
      b.onclick = async () => {
        try {
          const uid = b.dataset.id;
          const u = users.find((x) => String(x.id) === String(uid));
          await api(`/users/${uid}/disabled`, { method: "PUT", body: { disabled: !u.disabled } });
          toast(u.disabled ? "account enabled" : "account disabled");
          loadUsers();
        } catch (err) { $("u-error").textContent = err.message; }
      };
    });
  } catch (e) {
    // 403 => not an admin; hide the card entirely.
    $("users-card").classList.add("hidden");
  }
}

async function loadKeys() {
  try {
    const res = await api(`/keys?include_revoked=${state.keysShowRevoked ? "true" : "false"}`);
    $("k-include-revoked").textContent = state.keysShowRevoked ? "hide revoked" : "show revoked";
    $("keys-rows").innerHTML = res.items.map(keysRow).join("")
      || `<tr><td colspan="9" class="muted"><div class="empty-inner">
           <p>No API keys yet.</p>
           <p class="muted small">Create one below to let a SIEM pull the feed.
              Keys are shown once — copy the new key when you create it.</p>
         </div></td></tr>`;
    $("keys-rows").querySelectorAll("button[data-act]").forEach((b) => {
      b.onclick = async () => {
        const id = b.dataset.id, act = b.dataset.act;
        try {
          if (act === "revoke") {
            if (!confirm("Revoke this key? It will stop working immediately.")) return;
            await api(`/keys/${id}`, { method: "DELETE" });
            toast("revoked"); loadKeys();
          } else if (act === "rotate") {
            if (!confirm("Rotate this key? The old key stops working, a new one is issued.")) return;
            const r = await api(`/keys/${id}/rotate`, { method: "POST" });
            state.reveal[r.id] = r.key;
            showNewKey(`${r.name} key rotated — copy the NEW key now:`, r.key);
            toast("rotated"); loadKeys();
          } else if (act === "reveal") {
            const plain = state.reveal[id];
            if (!plain) return;
            copyText(plain).then(
              () => toast("key copied to clipboard"),
              () => toast("copy failed — select it in the box", true),
            );
          }
        } catch (e) { $("k-error").textContent = e.message; }
      };
    });
  } catch (e) { $("k-error").textContent = e.message; }
}

async function createKey() {
  $("k-error").textContent = "";
  hideNewKey();
  const platform = $("k-platform").value;
  $("k-platform-hint").innerHTML = platformHint(platform);
  try {
    const res = await api("/keys", { method: "POST", body: {
      name: $("k-name").value.trim(), scopes: $("k-scopes").value, platform } });
    state.reveal[res.id] = res.key;
    showNewKey(`key "${res.name}" created — shown once, copy it now:`, res.key);
    $("k-name").value = "";
    loadKeys();
  } catch (e) { $("k-error").textContent = e.message; }
}

/* ================= push ================= */
async function loadPush() {
  try {
    const res = await api("/push");
    $("push-targets").innerHTML = res.targets.length
      ? res.targets.map((t) => `<span class="chip ${t.enabled ? "on" : ""}">${esc(t.name)} <span class="muted">${esc(t.type)}</span></span>`).join("")
      : '<span class="muted small">no targets configured in config/push.yaml</span>';
    $("push-rows").innerHTML = res.log.map((l) => `
      <tr><td>${esc(l.target)}</td><td>${esc(l.status)}</td><td>${l.sent}</td>
      <td class="muted small">${esc(l.detail)}</td><td class="muted small">${esc(l.pushed_at)}</td></tr>`).join("")
      || `<tr><td colspan="5" class="muted">nothing pushed yet</td></tr>`;
  } catch (e) { $("p-error").textContent = e.message; }
}
async function triggerPush() {
  $("p-error").textContent = "";
  try {
    const res = await api("/push", { method: "POST", body: {} });
    if (!res.enabled) { $("p-error").textContent = res.detail || "push disabled"; return; }
    toast(`pushed ${res.sent} rows`);
    loadPush();
  } catch (e) { $("p-error").textContent = e.message; }
}

/* ================= collection run ================= */
async function triggerRun() {
  try {
    await api("/run", { method: "POST" });
    toast("collection started");
    pollRun();
  } catch (e) { toast(e.message, true); }
}
async function pollRun() {
  clearInterval(state.runTimer);
  const tick = async () => {
    try {
      const s = await api("/run");
      if (s.running) {
        $("btn-run").textContent = "Running…";
        $("btn-run").disabled = true;
        $("last-run").textContent = `running since ${s.started_at}`;
      } else {
        $("btn-run").innerHTML = '<span class="ico">▶</span><span class="lbl">Run</span>';
        $("btn-run").disabled = false;
        clearInterval(state.runTimer);
        if (s.last_error) { toast("run failed: " + s.last_error, true); }
        else if (s.last_stats) {
          toast(`cycle done: ${s.last_stats.rows_written} rows written`);
          loadStats(); loadFolders(); loadRows();
        }
      }
    } catch (e) { clearInterval(state.runTimer); }
  };
  await tick();
  state.runTimer = setInterval(tick, 3000);
}

/* ================= API page ================= */
function showPage(page, scrollTo = null) {
  state.page = page;
  $("page-iocs").classList.toggle("hidden", page !== "iocs");
  $("page-api").classList.toggle("hidden", page !== "api");
  document.querySelectorAll("#side-nav .nav").forEach((li) => li.classList.remove("on"));
  if (page === "api") { $("nav-api").classList.add("on"); populateApiPage(); }
  else { renderNav(); }
  if (scrollTo) setTimeout(() => $("page-api").querySelector(scrollTo).scrollIntoView({ behavior: "smooth" }), 60);
}
function populateApiPage() {
  const base = window.location.origin;
  const key = state.key ? `${state.key.slice(0, 11)}` : "<key>";
  const q = (p) => {
    const u = new URLSearchParams();
    if (state.q) u.set("q", state.q);
    if (state.folder) u.set("folder_id", state.folder.id);
    return u.toString();
  };
  $("api-base").textContent = `${base}/api/v1`;
  $("api-key-short").textContent = key;
  const params = q();
  const feedBase = `${base}/api/v1/iocs${params ? "?" + params : ""}`;
  $("api-feed").textContent = `curl -H "X-API-Key: ${key}" "${feedBase}&format=csv"`;
  $("api-feed-json").textContent = `GET ${feedBase}&format=json&min_severity=HIGH`;
  $("api-feed-stix").textContent = `curl -H "X-API-Key: ${key}" "${feedBase}&format=stix"`;
  $("api-ioc-get").textContent = `GET ${base}/api/v1/iocs/<TYPE>/<VALUE>  # e.g. /api/v1/iocs/Domain/evil.example.com`;
  $("api-copy-feed").onclick = async () => {
    try { await copyText($("api-feed").textContent); toast("curl copied"); }
    catch (e) { toast("copy failed", true); }
  };
}

/* ================= columns menu ================= */
function applyHideCols() {
  const table = $("iocs");
  ["ioc", "ioc_type", "severity", "confidence", "category", "malware", "folders", "last_seen"]
    .forEach((c) => table.classList.toggle("hide-" + c, state.hideCols.includes(c)));
}
function toggleColumnMenu() {
  const menu = $("columns-menu");
  menu.classList.toggle("hidden");
  if (!menu.classList.contains("hidden")) posPopover(menu, $("btn-columns"));
}

/* ================= wiring ================= */
function init() {
  $("n-type").innerHTML = ["IPv4","IPv6","Domain","URL","SHA256","SHA1","MD5","Email",
    "File-Name","CVE","Malware","Threat-Actor","Campaign"]
    .map((t) => `<option${t === "Domain" ? " selected" : ""}>${t}</option>`).join("");

  applyHideCols();

  /* login: username / password */
  $("login-form").onsubmit = async (e) => {
    e.preventDefault();
    const username = $("login-username").value.trim();
    const password = $("login-password").value;
    const errEl = $("login-error");
    if (!username || !password) {
      errEl.textContent = "enter your username and password";
      return;
    }
    errEl.textContent = "";
    $("login-btn").disabled = true;
    try {
      const res = await api("/auth/login", { method: "POST", body: { username, password } });
      state.key = res.key;
      localStorage.setItem("ioc_key", res.key);
      $("login-password").value = "";
      hideLogin();
      boot();
    } catch (err) {
      errEl.textContent = err.message === "API key required"
        ? "invalid username or password" : err.message;
    } finally {
      $("login-btn").disabled = false;
    }
  };

  /* login: first-run admin provisioning */
  $("prov-btn").onclick = async () => {
    const username = $("prov-username").value.trim();
    const password = $("prov-password").value;
    const errEl = $("prov-error");
    errEl.textContent = "";
    if (!username || password.length < 8) {
      errEl.textContent = "username required, password at least 8 characters";
      return;
    }
    $("prov-btn").disabled = true;
    try {
      await api("/auth/provision", { method: "POST", body: { username, password } });
      const res = await api("/auth/login", { method: "POST", body: { username, password } });
      state.key = res.key;
      localStorage.setItem("ioc_key", res.key);
      $("prov-password").value = "";
      hideLogin();
      boot();
      toast(`account ${res.username} created — signed in`);
    } catch (err) {
      errEl.textContent = err.message;
      refreshLoginMode();
    } finally {
      $("prov-btn").disabled = false;
    }
  };

  /* login: self-service registration with role selection */
  $("login-register-toggle").onclick = () => {
    const reg = $("login-register");
    reg.classList.toggle("hidden");
    $("login-signin").classList.toggle("hidden", !reg.classList.contains("hidden"));
    if (!reg.classList.contains("hidden")) populateRoleSelect();
  };

  $("reg-btn").onclick = async () => {
    const username = $("reg-username").value.trim();
    const full_name = $("reg-fullname").value.trim();
    const role = $("reg-role").value;
    const password = $("reg-password").value;
    const errEl = $("reg-error");
    errEl.textContent = "";
    if (!username || password.length < 8) {
      errEl.textContent = "username required, password at least 8 characters";
      return;
    }
    $("reg-btn").disabled = true;
    try {
      const res = await api("/auth/register", { method: "POST",
        body: { username, password, full_name, role } });
      state.key = res.key;
      localStorage.setItem("ioc_key", res.key);
      $("reg-password").value = "";
      hideLogin();
      boot();
      toast(res.first_user
        ? `account ${res.username} created as admin — signed in`
        : `account ${res.username} created as ${res.role}`);
    } catch (err) {
      errEl.textContent = err.message === "API key required" ? "registration failed" : err.message;
    } finally {
      $("reg-btn").disabled = false;
    }
  };

  /* login: advanced API-key fallback */
  $("login-tools").onclick = () => $("login-advanced").classList.toggle("hidden");
  const connectWithKey = async () => {
    const key = $("login-key").value.trim();
    const errEl = $("login-adv-error");
    if (!key) { errEl.textContent = "paste an API key first"; return; }
    errEl.textContent = "";
    const prev = state.key;
    state.key = key;
    try {
      await api("/stats");
      localStorage.setItem("ioc_key", key);
      hideLogin();
      boot();
    } catch (e) {
      state.key = prev;
      errEl.textContent = e.message === "API key required" ? "key rejected" : e.message;
    }
  };
  $("login-keybtn").onclick = connectWithKey;
  $("login-key").onkeydown = (e) => { if (e.key === "Enter") connectWithKey(); };
  $("btn-logout").onclick = async () => {
    try { await api("/auth/logout", { method: "POST" }); } catch (e) { /* already gone */ }
    localStorage.removeItem("ioc_key");
    state.key = "";
    showLogin();
  };

  /* global search */
  $("search").oninput = () => {
    clearTimeout(state.timer);
    state.timer = setTimeout(() => { state.q = $("search").value.trim(); state.offset = 0; loadRows(); renderActiveFilters(); }, 300);
  };

  /* sidebar sections */
  document.querySelectorAll(".sec-head").forEach((head) => {
    if (head.classList.contains("static")) return;
    head.onclick = () => head.closest(".sec").classList.toggle("collapsed");
  });

  /* views + severity + folders */
  document.querySelectorAll("#side-nav .nav[data-view]").forEach((li) => {
    li.onclick = () => setActiveView(li.dataset.view);
  });
  $("severity-chips").querySelectorAll(".chip").forEach((c) => {
    c.onclick = () => {
      const s = c.dataset.sev;
      state.sev.has(s) ? state.sev.delete(s) : state.sev.add(s);
      syncSevChips(); state.offset = 0; loadRows();
    };
  });
  $("folder-search").oninput = renderFolders;

  /* sort / paging */
  document.querySelectorAll("thead th[data-sort]").forEach((th) => {
    th.onclick = () => {
      const col = th.dataset.sort;
      if (state.sort === col) state.order = state.order === "asc" ? "desc" : "asc";
      else { state.sort = col; state.order = "desc"; }
      loadRows();
    };
  });
  $("page-size").onchange = () => { state.limit = parseInt($("page-size").value, 10); state.offset = 0; loadRows(); };
  $("prev").onclick = () => { state.offset = Math.max(0, state.offset - state.limit); loadRows(); };
  $("next").onclick = () => { state.offset += state.limit; loadRows(); };

  /* export / refresh / columns */
  $("export-csv").onclick = () => download(`/iocs?${filters()}&format=csv`, "iocs.csv");
  $("export-stix").onclick = () => download(`/iocs?${filters()}&format=stix`, "iocs.stix.json");
  $("btn-refresh").onclick = () => { loadStats(); loadFolders(); loadRows(); };
  $("btn-columns").onclick = () => toggleColumnMenu();
  $("columns-menu").querySelectorAll("input[data-col]").forEach((cb) => {
    cb.onclick = () => {
      const col = cb.dataset.col;
      const i = state.hideCols.indexOf(col);
      if (cb.checked && i >= 0) state.hideCols.splice(i, 1);
      else if (!cb.checked && i < 0) state.hideCols.push(col);
      localStorage.setItem("ioc_hide_cols", JSON.stringify(state.hideCols));
  applyHideCols();
  syncStickyOffsets();
  window.addEventListener("resize", syncStickyOffsets);
    };
  });

  /* bulk */
  $("check-all").onchange = () => {
    const on = $("check-all").checked;
    document.querySelectorAll("#rows .cb").forEach((cb) => {
      cb.checked = on;
      on ? state.selectedSet.set(cb.value, true) : state.selectedSet.delete(cb.value);
    });
    updateBulk();
  };
  $("bulk-del").onclick = bulkDelete;
  $("bulk-apply").onclick = bulkApply;
  $("bulk-clear").onclick = () => { state.selectedSet = new Map(); updateBulk(); syncHeaderCheck(); };

  /* new IOC + folder modal */
  $("btn-new").onclick = showNewIoc;
  $("n-cancel").onclick = () => $("modal-new").classList.add("hidden");
  $("n-save").onclick = createIoc;
  $("btn-folder-new").onclick = () => $("modal-folder").classList.remove("hidden");
  $("f-cancel").onclick = () => $("modal-folder").classList.add("hidden");
  $("f-save").onclick = createFolder;

  /* drawer */
  $("d-close").onclick = () => $("drawer").classList.add("hidden");
  $("d-save").onclick = saveDrawer;
  $("d-delete").onclick = deleteDrawer;
  $("d-folder-add-btn").onclick = addToFolder;

  /* keys + push + run + api page */
  const openApiPage = () => { showPage("api", ".keys-card"); loadKeys(); loadUsers(); };
  $("btn-keys").onclick = openApiPage;
  $("nav-api").onclick = openApiPage;
  $("k-include-revoked").onclick = () => { state.keysShowRevoked = !state.keysShowRevoked; loadKeys(); };
  $("k-create").onclick = createKey;
  $("k-platform").onchange = () => { $("k-platform-hint").innerHTML = platformHint($("k-platform").value); };
  $("btn-push").onclick = () => { $("modal-push").classList.remove("hidden"); loadPush(); };
  $("p-close").onclick = () => $("modal-push").classList.add("hidden");
  $("p-trigger").onclick = triggerPush;
  $("btn-run").onclick = triggerRun;

  /* keyboard */
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      $("drawer").classList.add("hidden");
      $("row-menu").classList.add("hidden");
      $("columns-menu").classList.add("hidden");
      ["modal-new", "modal-folder", "modal-push"].forEach((id) => $(id).classList.add("hidden"));
    }
    if (e.key === "/" && document.activeElement.tagName !== "INPUT") { e.preventDefault(); $("search").focus(); }
  });

  /* close popovers / overlays on outside click */
  document.addEventListener("click", (e) => {
    if (!$("row-menu").classList.contains("hidden") && !e.target.closest("#row-menu"))
      $("row-menu").classList.add("hidden");
    if (!$("columns-menu").classList.contains("hidden") &&
        !e.target.closest("#columns-menu") && e.target.id !== "btn-columns")
      $("columns-menu").classList.add("hidden");
  });
  document.querySelectorAll(".overlay").forEach((ov) => {
    ov.addEventListener("click", (e) => { if (e.target === ov && ov.id !== "login") ov.classList.add("hidden"); });
  });
}

async function boot() {
  try {
    await loadStats();
    hideLogin();
    await Promise.all([loadFolders(), loadRows()]);
    pollRun();
  } catch (e) { setConn("err", "error"); console.error(e); }
}

function escapeAttr(s) { return esc(s).replace(/"/g, "&quot;"); }
try { init(); }
catch (e) { console.error("init failed", e); toast("dashboard wiring failed: " + e.message, true); }
if (state.key) boot(); else showLogin();