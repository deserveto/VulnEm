/* VulnEm provider picker (Setup): reads the embedded catalog JSON and keeps
   the model hint + example datalist in sync with the selected provider.
   All injected text goes through textContent — never innerHTML. */
"use strict";

(function () {
  const dataEl = document.getElementById("provider-data");
  const select = document.getElementById("provider");
  const hint = document.getElementById("model-hint");
  const datalist = document.getElementById("model-examples");
  if (!dataEl || !select) return;

  let catalog;
  try {
    catalog = JSON.parse(dataEl.textContent || "{}");
  } catch {
    return; // catalog is decoration — a broken blob must not break the form
  }

  function apply(prefix) {
    const row = catalog[prefix];
    if (!row) {
      if (hint) {
        hint.textContent = "Custom provider — any litellm prefix works; " +
          "set <PREFIX>_API_KEY in .env if it follows the convention.";
      }
      if (datalist) datalist.replaceChildren();
      return;
    }
    if (hint) {
      const key = row.key_var ? ("key env var " + row.key_var)
        : "no API key needed";
      hint.textContent = row.label + " — " + key +
        (row.note ? ". " + row.note : ".");
    }
    if (datalist) {
      datalist.replaceChildren(...row.examples.map((ex) => {
        const option = document.createElement("option");
        option.value = ex;
        return option;
      }));
    }
  }

  select.addEventListener("change", () => apply(select.value));
  apply(select.value);
})();
