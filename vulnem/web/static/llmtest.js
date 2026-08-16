/* VulnEm "Test connection" (Setup + New scan model override): one minimal
   provider round-trip with the model in the form. On Setup a typed API key
   is used when present; otherwise (and on New scan) the saved key is tested.
   All injected text goes through textContent — never innerHTML. */
"use strict";

const testBtn = document.getElementById("test-llm-btn");
const testOut = document.getElementById("test-llm-result");

function showResult(ok, text) {
  testOut.hidden = false;
  testOut.textContent = text;
  testOut.className = ok ? "ok-text" : "err-text";
}

if (testBtn && testOut) {
  testBtn.addEventListener("click", async () => {
    const model = document.getElementById("model").value.trim();
    const apiKeyInput = document.getElementById("api_key"); // Setup only
    const apiKey = apiKeyInput ? apiKeyInput.value.trim() : "";
    const label = testBtn.textContent;
    testBtn.disabled = true;
    testBtn.textContent = "Testing…";
    testOut.hidden = true;
    try {
      const resp = await fetch("/setup/test-llm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: model, api_key: apiKey }),
        cache: "no-store",
      });
      const data = await resp.json().catch(() => null);
      if (data && data.ok) {
        showResult(true, "✓ Connected — " + (data.model || model) +
                   " answered in " + data.latency_ms + " ms.");
      } else {
        showResult(false, "✗ " + ((data && data.error) || "Connection failed."));
      }
    } catch {
      showResult(false, "✗ Could not reach the local server — is vulnem ui " +
                 "still running?");
    } finally {
      testBtn.disabled = false;
      testBtn.textContent = label;
    }
  });
}
