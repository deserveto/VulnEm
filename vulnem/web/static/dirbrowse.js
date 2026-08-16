/* VulnEm folder picker (New scan → white-box source directory): browsers
   never expose absolute local paths, so the app's own /browse endpoint walks
   the operator's filesystem instead. Directory names render via
   textContent — never innerHTML. */
"use strict";

(function () {
  const btn = document.getElementById("browse-dirs-btn");
  const dlg = document.getElementById("dir-browser");
  const pathEl = document.getElementById("dir-browser-path");
  const listEl = document.getElementById("dir-browser-list");
  const upBtn = document.getElementById("dir-browser-up");
  const selectBtn = document.getElementById("dir-browser-select");
  const cancelBtn = document.getElementById("dir-browser-cancel");
  const input = document.getElementById("source_dir");
  if (!btn || !dlg || !pathEl || !listEl || !upBtn || !selectBtn || !input ||
      typeof dlg.showModal !== "function") {
    return; // unsupported browser: the text field still works alone
  }
  let current = "";
  let parentPath = "";

  async function load(path) {
    const query = path ? "?path=" + encodeURIComponent(path) : "";
    const resp = await fetch("/browse" + query, { cache: "no-store" });
    if (!resp.ok) {
      pathEl.textContent = "Could not open " + (path || "home directory");
      listEl.replaceChildren();
      upBtn.disabled = true;
      return;
    }
    const data = await resp.json();
    current = data.path;
    parentPath = data.parent || "";
    pathEl.textContent = current;
    upBtn.disabled = !parentPath;
    listEl.replaceChildren(...data.dirs.map((name) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "dir-browser-entry";
      row.textContent = name + "/";
      row.addEventListener("click", () => load(current + "/" + name));
      return row;
    }));
  }

  btn.addEventListener("click", async () => {
    dlg.showModal();
    await load(input.value.trim() || "");  // resume from a typed path if valid
  });
  upBtn.addEventListener("click", () => parentPath && load(parentPath));
  selectBtn.addEventListener("click", () => {
    input.value = current;
    dlg.close();
  });
  cancelBtn.addEventListener("click", () => dlg.close());
})();
