"use strict";

const STORAGE_KEY = "menhera-ddns.credentials.v1";
const createForm = document.querySelector("#create-form");
const importForm = document.querySelector("#import-form");
const importToggle = document.querySelector("#import-toggle");
const recordList = document.querySelector("#record-list");
const emptyState = document.querySelector("#empty-state");
const recordTemplate = document.querySelector("#record-template");
const notice = document.querySelector("#notice");
const zoneBrand = document.querySelector("#zone-brand");
const zoneName = document.querySelector("#zone-name");
const zoneSuffix = document.querySelector("#zone-suffix");
const hostnameInput = document.querySelector("#hostname");
const hostnamePreview = document.querySelector("#hostname-preview");

let credentials = loadCredentials();
let noticeTimer;
let configuredZone = "";

function loadCredentials() {
  try {
    const value = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    if (!Array.isArray(value)) return [];
    return value.filter((item) =>
      item && typeof item.name === "string" && /^[a-f0-9]{32}$/i.test(item.token));
  } catch (_) {
    return [];
  }
}

function saveCredentials() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
    return true;
  } catch (_) {
    return false;
  }
}

function showNotice(message, isError = false) {
  clearTimeout(noticeTimer);
  notice.textContent = message;
  notice.classList.toggle("error", isError);
  notice.hidden = false;
  noticeTimer = setTimeout(() => { notice.hidden = true; }, 5000);
}

async function request(path, parameters) {
  const query = new URLSearchParams(parameters);
  const response = await fetch(`${path}?${query}`, {
    method: "POST",
    headers: { "accept": "application/json" },
  });
  let body;
  try {
    body = await response.json();
  } catch (_) {
    throw new Error(`Server returned HTTP ${response.status}`);
  }
  if (!response.ok || body.error) {
    throw new Error(body.error || `Server returned HTTP ${response.status}`);
  }
  return body;
}

function qualifyName(name) {
  const value = name.trim();
  if (!configuredZone || !value || value.includes(".")) return value;
  return `${value}.${configuredZone}`;
}

function updateHostnamePreview() {
  const label = hostnameInput.value.trim() || "hostname";
  hostnamePreview.textContent = configuredZone
    ? `Complete name: ${qualifyName(label)}`
    : "Complete name unavailable until zone information loads";
}

async function loadInfo() {
  try {
    const response = await fetch("/info", { headers: { "accept": "application/json" } });
    const body = await response.json();
    if (!response.ok || body.error || typeof body.zone !== "string" || !body.zone) {
      throw new Error(body.error || `Server returned HTTP ${response.status}`);
    }
    configuredZone = body.zone.endsWith(".") ? body.zone : `${body.zone}.`;
    zoneBrand.textContent = `Dynamic DNS · ${configuredZone}`;
    zoneName.textContent = configuredZone;
    zoneSuffix.textContent = `.${configuredZone}`;
    importForm.elements.hostname.placeholder = `laptop.${configuredZone}`;
    document.title = `${configuredZone} · menhera-ddns`;
    updateHostnamePreview();
    render();
  } catch (error) {
    zoneBrand.textContent = "Dynamic DNS · zone unavailable";
    zoneSuffix.textContent = "";
    updateHostnamePreview();
    showNotice(`Could not load DDNS zone: ${error.message}`, true);
  }
}

function setBusy(button, busy, busyLabel) {
  if (busy) {
    button.dataset.label = button.textContent;
    button.textContent = busyLabel;
  } else {
    button.textContent = button.dataset.label;
  }
  button.disabled = busy;
}

async function copyText(value) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch (_) {
      // The fallback also works on many non-secure legacy HTTP deployments.
    }
  }
  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.append(input);
  input.select();
  const copied = document.execCommand("copy");
  input.remove();
  if (!copied) throw new Error("The browser did not allow clipboard access");
}

function render() {
  recordList.replaceChildren();
  emptyState.hidden = credentials.length !== 0;

  for (const credential of credentials) {
    const fragment = recordTemplate.content.cloneNode(true);
    const name = fragment.querySelector(".record-name");
    const detail = fragment.querySelector(".record-detail");
    const updateButton = fragment.querySelector(".update-button");
    const copyButton = fragment.querySelector(".copy-button");
    const deleteButton = fragment.querySelector(".delete-button");

    const displayName = qualifyName(credential.name) || "Imported credential";
    name.textContent = displayName;
    if (credential.address) {
      detail.textContent = `Last set to ${credential.address}`;
    }

    copyButton.addEventListener("click", async () => {
      try {
        await copyText(credential.token);
        showNotice("Token copied to the clipboard");
      } catch (error) {
        showNotice(error.message, true);
      }
    });

    updateButton.addEventListener("click", async () => {
      setBusy(updateButton, true, "Updating…");
      copyButton.disabled = true;
      deleteButton.disabled = true;
      try {
        const result = await request("/update", { token: credential.token });
        credential.name = result.hostname;
        credential.address = result.address;
        saveCredentials();
        render();
        showNotice(`${result.hostname} now points to ${result.address}`);
      } catch (error) {
        setBusy(updateButton, false);
        copyButton.disabled = false;
        deleteButton.disabled = false;
        showNotice(error.message, true);
      }
    });

    deleteButton.addEventListener("click", async () => {
      if (!window.confirm(`Permanently delete ${displayName}?`)) return;
      setBusy(deleteButton, true, "Deleting…");
      updateButton.disabled = true;
      copyButton.disabled = true;
      try {
        const result = await request("/delete", { token: credential.token });
        credentials = credentials.filter((item) => item.token !== credential.token);
        saveCredentials();
        render();
        showNotice(`${result.hostname} was deleted`);
      } catch (error) {
        setBusy(deleteButton, false);
        updateButton.disabled = false;
        copyButton.disabled = false;
        showNotice(error.message, true);
      }
    });

    recordList.append(fragment);
  }
}

createForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = createForm.querySelector("button");
  const input = createForm.elements.hostname;
  setBusy(button, true, "Reserving…");
  try {
    const result = await request("/create", { hostname: input.value });
    const createdName = qualifyName(input.value);
    credentials.push({ name: createdName, token: result.token });
    const saved = saveCredentials();
    createForm.reset();
    updateHostnamePreview();
    render();
    showNotice(saved
      ? `${createdName} was reserved; its token is saved in this browser`
      : `${createdName} was reserved, but browser storage is unavailable; copy its token now`,
    !saved);
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    setBusy(button, false);
  }
});

hostnameInput.addEventListener("input", updateHostnamePreview);

importToggle.addEventListener("click", () => {
  const opening = importForm.hidden;
  importForm.hidden = !opening;
  importToggle.setAttribute("aria-expanded", String(opening));
  if (opening) importForm.elements.hostname.focus();
});

importForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const token = importForm.elements.token.value.toLowerCase();
  const name = importForm.elements.hostname.value.trim();
  const existing = credentials.find((item) => item.token === token);
  if (existing) {
    existing.name = name || existing.name;
  } else {
    credentials.push({ name, token });
  }
  const saved = saveCredentials();
  importForm.reset();
  importForm.hidden = true;
  importToggle.setAttribute("aria-expanded", "false");
  render();
  showNotice(saved ? "Credential saved in this browser" : "Browser storage is unavailable", !saved);
});

render();
loadInfo();
