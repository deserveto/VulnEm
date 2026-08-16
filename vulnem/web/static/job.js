/* VulnEm job page: poll status.json and update the badge / log / run link.
   All injected text goes through textContent — never innerHTML. */
"use strict";

const TERMINAL = ["done", "failed", "stopped"];
const POLL_MS = 1000;

let logPinned = true; // auto-scroll unless the user scrolled up

function render(job) {
  const badge = document.getElementById("job-status");
  badge.textContent = job.status;
  badge.className = "badge jstatus-" + job.status;

  const link = document.getElementById("job-run-link");
  if (job.run_dir && !link.firstChild) {
    const a = document.createElement("a");
    a.href = "/runs/" + encodeURIComponent(job.run_dir);
    a.textContent = "Open live run view →";
    link.appendChild(a);
  }

  const log = document.getElementById("job-log");
  log.textContent = (job.log || []).join("\n");
  if (logPinned) log.scrollTop = log.scrollHeight;

  if (TERMINAL.includes(job.status)) {
    const btn = document.getElementById("job-stop-btn");
    if (btn) btn.disabled = true;
  }
}

async function poll() {
  const url = window.VULNEM_JOB_STATUS_URL;
  if (!url) return;
  let alive = true;
  while (alive) {
    try {
      const resp = await fetch(url, { cache: "no-store" });
      if (resp.status === 404) break; // server lost the job (restart)
      const job = await resp.json();
      render(job);
      if (TERMINAL.includes(job.status)) alive = false;
    } catch {
      break; // server gone — leave the page as-is
    }
    if (alive) await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
}

const logBox = document.getElementById("job-log");
if (logBox) {
  logBox.addEventListener("scroll", () => {
    logPinned = logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 30;
  });
}
poll();
