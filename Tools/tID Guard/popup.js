const tenantNameInput = document.getElementById("tenantName");
const tenantIdInput = document.getElementById("tenantId");
const saveButton = document.getElementById("save");
const applyButton = document.getElementById("apply");

const hostnameElement = document.getElementById("hostname");
const statusElement = document.getElementById("status");
const configuredTidElement = document.getElementById("configuredTid");
const currentTidElement = document.getElementById("currentTid");

function normalizeTenantId(value) {
  return String(value || "").trim();
}

function isValidGuid(value) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(value);
}

function setStatus(state, text) {
  statusElement.className = `status ${state}`;
  statusElement.textContent = text;
}

async function loadConfig() {
  const { tenantId, tenantName } = await chrome.storage.sync.get([
    "tenantId",
    "tenantName"
  ]);

  tenantIdInput.value = tenantId || "";
  tenantNameInput.value = tenantName || "";
}

async function refreshStatus() {
  chrome.runtime.sendMessage({ action: "getStatus" }, response => {
    if (!response) {
      setStatus("gray", "Unable to read current tab");
      return;
    }

    hostnameElement.textContent = response.hostname || "-";
    configuredTidElement.textContent = response.tenantId || "-";
    currentTidElement.textContent = response.currentTid || "-";

    if (response.state === "green") {
      setStatus("green", "Correct tenant");
      applyButton.disabled = true;
      return;
    }

    if (response.state === "red") {
      setStatus("red", response.reason || "Wrong tenant");
      applyButton.disabled = false;
      return;
    }

    setStatus("gray", response.reason || "Not active");
    applyButton.disabled = !response.supported || !response.tenantId;
  });
}

saveButton.addEventListener("click", async () => {
  const tenantId = normalizeTenantId(tenantIdInput.value);
  const tenantName = tenantNameInput.value.trim();

  if (!tenantId) {
    setStatus("gray", "Tenant ID is required");
    return;
  }

  if (!isValidGuid(tenantId)) {
    setStatus("red", "Tenant ID must be a valid GUID");
    return;
  }

  await chrome.storage.sync.set({
    tenantId,
    tenantName
  });

  await refreshStatus();
});

applyButton.addEventListener("click", async () => {
  chrome.runtime.sendMessage({ action: "applyTid" }, response => {
    if (!response?.success) {
      setStatus("red", response?.reason || "Could not switch tenant");
      return;
    }

    setStatus("gray", "Switching tenant...");
    window.close();
  });
});

loadConfig().then(refreshStatus);
