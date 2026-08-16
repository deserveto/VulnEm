/* VulnEm theme toggle: light (default) <-> dark, persisted per browser.
   The <head> inline script in base.html applies the stored theme before
   first paint; this wires the button and keeps the label in sync. */
"use strict";

(function () {
  const root = document.documentElement;
  const btn = document.getElementById("theme-toggle");

  function current() {
    return root.dataset.theme === "dark" ? "dark" : "light";
  }

  function apply(theme) {
    if (theme === "dark") root.dataset.theme = "dark";
    else delete root.dataset.theme;
    if (!btn) return;
    // icons swap via CSS on [data-theme]; the button still needs its name
    const next = theme === "dark" ? "light" : "dark";
    btn.setAttribute("aria-label", `Switch to ${next} theme`);
    btn.setAttribute("aria-pressed", String(theme === "dark"));
  }

  let stored = null;
  try {
    stored = localStorage.getItem("vulnem-theme");
  } catch (e) { /* unreadable storage — light default */ }
  apply(stored === "dark" ? "dark" : "light");

  if (btn) {
    btn.addEventListener("click", () => {
      const next = current() === "dark" ? "light" : "dark";
      try {
        localStorage.setItem("vulnem-theme", next);
      } catch (e) { /* keep the toggle working even if storage refuses */ }
      apply(next);
    });
  }
})();
