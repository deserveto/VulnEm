/* VulnEm run page: render the bootstrap snapshot, then live-update over SSE.
   All injected text goes through textContent — never innerHTML. */
"use strict";

const STATUS_CLASS = {
  pending: "st-pending", running: "st-running", waiting: "st-waiting",
  completed: "st-completed", stopped: "st-stopped", crashed: "st-crashed",
  failed: "st-failed",
};
const TONE_CLASS = {
  text: "tn-text", tool: "tn-tool", finding: "tn-finding", agent: "tn-agent",
  msg: "tn-msg", warn: "tn-warn", sys: "tn-sys", critical: "tn-critical",
  info: "tn-info",
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function fmtNum(n) { return (n === null || n === undefined) ? "—" : Number(n).toLocaleString(); }

function hhmmss(ts) { return (ts && ts.length >= 19) ? ts.slice(11, 19) : ""; }

let streamPinned = true; // auto-scroll unless the user scrolled up

function renderStats(meta) {
  const stats = document.getElementById("stats");
  stats.textContent = "";
  stats.append(
    el("span", null, `turns ${fmtNum(meta.turns_used)}/${meta.budget_turns ?? "?"}`),
    "  tokens ", el("span", null, fmtNum(meta.total_tokens)),
    "  flows ", el("span", null, fmtNum(meta.flow_count)),
    "  blocked ", el("span", null, fmtNum(meta.blocked_count)),
    "  shots ", el("span", null, fmtNum(meta.screenshots)),
    "  findings ", el("span", null, fmtNum(meta.findings_total)),
  );
}

function agentRow(view) {
  const li = el("li");
  li.append(el("span", "dot " + (STATUS_CLASS[view.status] || "st-pending")));
  li.append(el("span", "agent-name", view.name));
  li.append(el("span", "dim", ` ${view.status} · ${view.turns}t ${fmtNum(view.tokens)} tok` +
    (view.findings ? ` · ${view.findings}f` : "")));
  return li;
}

function renderAgents(agents) {
  const root = document.getElementById("agents");
  root.textContent = "";
  const children = new Map();
  for (const a of agents) {
    const key = a.parent_id || "";
    if (!children.has(key)) children.set(key, []);
    children.get(key).push(a);
  }
  const build = (agent) => {
    const li = agentRow(agent);
    const kids = (children.get(agent.agent_id) || [])
      .sort((a, b) => a.name.localeCompare(b.name));
    if (kids.length) {
      const ul = el("ul");
      kids.forEach((k) => ul.appendChild(build(k)));
      li.append(ul);
    }
    return li;
  };
  const roots = (children.get("") || []).sort((a, b) =>
    (b.role === "root") - (a.role === "root") || a.name.localeCompare(b.name));
  roots.forEach((a) => root.appendChild(build(a)));
}

function streamLine(item) {
  const line = el("div", "line " + (TONE_CLASS[item.tone] || "tn-text"));
  line.append(el("span", "ts", hhmmss(item.ts) || "--:--:--"));
  if (item.agent) line.append(el("span", "who", item.agent));
  line.append(el("span", "txt", item.text));
  return line;
}

function appendStream(items, streamTotal) {
  const box = document.getElementById("stream");
  for (const item of items) box.appendChild(streamLine(item));
  const cap = 2000;
  while (box.childNodes.length > cap) box.removeChild(box.firstChild);
  document.getElementById("stream-count").textContent =
    streamTotal ? `(${streamTotal})` : "";
  if (streamPinned) box.scrollTop = box.scrollHeight;
}

function sevBadge(sev) {
  return el("span", "badge sev-bg-" + sev, sev);
}

function renderFindings(findings) {
  const body = document.getElementById("findings");
  body.textContent = "";
  document.getElementById("findings-count").textContent =
    `(${findings.length})`;
  for (const f of findings) {
    const tr = el("tr");
    const sev = el("td");
    sev.append(sevBadge(f.severity));
    tr.append(sev, el("td", "f-title", f.title), el("td", "mono dim", f.url || "—"),
              el("td", "dim", f.by));
    body.appendChild(tr);
  }
}

function setStatus(status) {
  const badge = document.getElementById("status-badge");
  badge.textContent = status;
  badge.className = "badge status-" + status;
}

function fullRender(snap) {
  setStatus(snap.status || "running");
  renderStats(snap.meta);
  renderAgents(snap.agents || []);
  const box = document.getElementById("stream");
  box.textContent = "";
  appendStream(snap.stream || [], snap.stream_total);
  renderFindings(snap.findings || []);
}

function deltaRender(delta) {
  if (delta.meta) renderStats(delta.meta);
  if (delta.agents) renderAgents(delta.agents);
  if (delta.findings) renderFindings(delta.findings);
  if (delta.stream) appendStream(delta.stream, delta.stream_total);
}

const bootEl = document.getElementById("bootstrap");
if (bootEl) {
  const boot = JSON.parse(bootEl.textContent);
  fullRender(boot);

  const streamBox = document.getElementById("stream");
  streamBox.addEventListener("scroll", () => {
    streamPinned = streamBox.scrollTop + streamBox.clientHeight
      >= streamBox.scrollHeight - 30;
  });

  const url = window.VULNEM_EVENTS_URL;
  if (url && window.EventSource) {
    const es = new EventSource(url);
    es.addEventListener("snap", (ev) => fullRender(JSON.parse(ev.data)));
    es.addEventListener("delta", (ev) => deltaRender(JSON.parse(ev.data)));
    es.addEventListener("end", () => {
      es.close();
      setStatus("done");
    });
    es.onerror = () => {
      if (boot.meta && boot.meta.stop_reason) { es.close(); setStatus("done"); }
    };
  }
}
