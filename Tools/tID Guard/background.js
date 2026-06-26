const ADMIN_HOSTS = [
  "portal.azure.com",
  "entra.microsoft.com",
  "admin.microsoft.com",
  "intune.microsoft.com",
  "security.microsoft.com",
  "defender.microsoft.com",
  "compliance.microsoft.com",
  "exchange.admin.microsoft.com",
  "endpoint.microsoft.com",
  "purview.microsoft.com"
];

chrome.runtime.onStartup.addListener(() => {
  chrome.storage.local.remove("activeTenant");
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.remove("activeTenant");
  setToolbarState("gray", "TID Guard\nNo active tenant set");
});

function storageGet(key) {
  return new Promise(resolve => {
    chrome.storage.local.get(key, result => resolve(result));
  });
}

function storageSet(value) {
  return new Promise(resolve => {
    chrome.storage.local.set(value, () => resolve());
  });
}

function storageRemove(key) {
  return new Promise(resolve => {
    chrome.storage.local.remove(key, () => resolve());
  });
}

function normalize(value) {
  return String(value || "").trim().toLowerCase();
}

function isSupportedAdminUrl(url) {
  return ADMIN_HOSTS.some(host =>
    url.hostname === host || url.hostname.endsWith("." + host)
  );
}

function getCurrentTid(rawUrl) {
  const url = new URL(rawUrl);
  return url.searchParams.get("tid");
}

function setTid(rawUrl, tenantId) {
  const url = new URL(rawUrl);

  if (!["http:", "https:"].includes(url.protocol)) {
    return rawUrl;
  }

  url.searchParams.delete("tid");
  url.searchParams.append("tid", tenantId);

  return url.toString();
}

function getState(rawUrl, activeTenant) {
  let url;

  try {
    url = new URL(rawUrl);
  } catch {
    return {
      state: "gray",
      reason: "Invalid URL",
      currentTid: null,
      supported: false
    };
  }

  if (!isSupportedAdminUrl(url)) {
    return {
      state: "gray",
      reason: "Not a supported Microsoft admin site",
      currentTid: null,
      supported: false
    };
  }

  if (!activeTenant?.tenantId) {
    return {
      state: "gray",
      reason: "No active tenant set",
      currentTid: getCurrentTid(rawUrl),
      supported: true
    };
  }

  const currentTid = getCurrentTid(rawUrl);

  if (!currentTid) {
    return {
      state: "red",
      reason: "No tenant ID found in URL",
      currentTid: null,
      supported: true
    };
  }

  if (normalize(currentTid) === normalize(activeTenant.tenantId)) {
    return {
      state: "green",
      reason: "Correct tenant",
      currentTid,
      supported: true
    };
  }

  return {
    state: "red",
    reason: "Different tenant ID found in URL",
    currentTid,
    supported: true
  };
}

async function getActiveTenant() {
  const result = await storageGet("activeTenant");
  return result.activeTenant || null;
}

function setToolbarState(state, title) {
  const iconPath = {
    green: "icons/green.png",
    red: "icons/red.png",
    gray: "icons/gray.png"
  }[state] || "icons/gray.png";

  chrome.action.setIcon({
    path: {
      "16": iconPath,
      "32": iconPath,
      "48": iconPath,
      "128": iconPath
    }
  });

  chrome.action.setBadgeText({
    text: state === "green" ? "OK" : state === "red" ? "!" : "-"
  });

  chrome.action.setBadgeBackgroundColor({
    color: state === "green" ? "#008000" : state === "red" ? "#cc0000" : "#777777"
  });

  chrome.action.setTitle({
    title
  });
}

async function updateToolbarForActiveTab() {
  const tabs = await chrome.tabs.query({
    active: true,
    lastFocusedWindow: true
  });

  const tab = tabs[0];
  const activeTenant = await getActiveTenant();

  if (!tab?.url) {
    setToolbarState("gray", "TID Guard\nNo active tab");
    return;
  }

  const result = getState(tab.url, activeTenant);

  const title = [
    "TID Guard",
    activeTenant?.tenantLabel ? `Active: ${activeTenant.tenantLabel}` : "Active: none",
    activeTenant?.tenantId ? `TID: ${activeTenant.tenantId}` : null,
    `Status: ${result.reason}`,
    result.currentTid ? `Current URL TID: ${result.currentTid}` : null
  ].filter(Boolean).join("\n");

  setToolbarState(result.state, title);
}

chrome.tabs.onUpdated.addListener(() => {
  updateToolbarForActiveTab();
});

chrome.tabs.onActivated.addListener(() => {
  updateToolbarForActiveTab();
});

chrome.windows.onFocusChanged.addListener(() => {
  updateToolbarForActiveTab();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "setActiveTenant") {
    storageSet({
      activeTenant: {
        tenantId: message.tenantId,
        tenantLabel: message.tenantLabel || "",
        createdAt: new Date().toISOString()
      }
    }).then(async () => {
      await updateToolbarForActiveTab();
      sendResponse({ success: true });
    });

    return true;
  }

  if (message.action === "clearActiveTenant") {
    storageRemove("activeTenant").then(async () => {
      await updateToolbarForActiveTab();
      sendResponse({ success: true });
    });

    return true;
  }

  if (message.action === "getStatus") {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, async tabs => {
      const tab = tabs[0];
      const activeTenant = await getActiveTenant();

      if (!tab?.url) {
        sendResponse({
          state: "gray",
          reason: "No active tab",
          activeTenant
        });
        return;
      }

      const result = getState(tab.url, activeTenant);

      sendResponse({
        ...result,
        activeTenant,
        currentUrl: tab.url,
        hostname: new URL(tab.url).hostname
      });
    });

    return true;
  }

  if (message.action === "applyTid") {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, async tabs => {
      const tab = tabs[0];
      const activeTenant = await getActiveTenant();

      if (!tab?.id || !tab?.url || !activeTenant?.tenantId) {
        sendResponse({
          success: false,
          reason: "Missing active tab or active tenant"
        });
        return;
      }

      const newUrl = setTid(tab.url, activeTenant.tenantId);

      chrome.tabs.update(tab.id, { url: newUrl }, async () => {
        await updateToolbarForActiveTab();
      });

      sendResponse({
        success: true,
        newUrl
      });
    });

    return true;
  }
});

updateToolbarForActiveTab();