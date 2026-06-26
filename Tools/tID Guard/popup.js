const tenantLabelInput = document.getElementById("tenantLabel");
const tenantIdInput = document.getElementById("tenantId");

const setActiveButton = document.getElementById("setActive");
const clearActiveButton = document.getElementById("clearActive");
const applyButton = document.getElementById("apply");

const hostnameElement = document.getElementById("hostname");
const statusElement = document.getElementById("status");
const activeTidElement = document.getElementById("activeTid");
const currentTidElement = document.getElementById("currentTid");

function clean(value) {
  return String(value || "").trim();
}

function isValidGuid(value) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(value);
}

function setStatus(state, text) {
  statusElement.className = `status ${state}`;
  statusElement.textContent = text;
}

function refreshStatus() {
  chrome.runtime.sendMessage({ action: "getStatus" }, response => {
    if (!response) {
      setStatus("gray", "Unable to read current tab");
      return;
    }

    const activeTenant = response.activeTenant;

    tenantLabelInput.value = activeTenant?.tenantLabel || "";
    tenantIdInput.value = activeTenant?.tenantId || "";

    hostnameElement.textContent = response.hostname || "-";
    activeTidElement.textContent = activeTenant?.tenantId || "-";
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
    applyButton.disabled = !response.supported || !activeTenant?.tenantId;
  });
}

setActiveButton.addEventListener("click", () => {
  const tenantId = clean(tenantIdInput.value);
  const tenantLabel = clean(tenantLabelInput.value);

  if (!tenantId) {
    setStatus("gray", "Tenant ID is required");
    return;
  }

  if (!isValidGuid(tenantId)) {
    setStatus("red", "Tenant ID must be a valid GUID");
    return;
  }

  chrome.runtime.sendMessage({
    action: "setActiveTenant",
    tenantId,
    tenantLabel
  }, response => {
    if (!response?.success) {
      setStatus("red", "Could not set active tenant");
      return;
    }

    refreshStatus();
  });
});

clearActiveButton.addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "clearActiveTenant" }, response => {
    if (!response?.success) {
      setStatus("red", "Could not clear active tenant");
      return;
    }

    tenantLabelInput.value = "";
    tenantIdInput.value = "";
    refreshStatus();
  });
});

applyButton.addEventListener("click", () => {
  chrome.runtime.sendMessage({ action: "applyTid" }, response => {
    if (!response?.success) {
      setStatus("red", response?.reason || "Could not switch tenant");
      return;
    }

    setStatus("gray", "Switching tenant...");
    window.close();
  });
});

refreshStatus();
