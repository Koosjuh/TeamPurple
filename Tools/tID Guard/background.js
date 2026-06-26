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

function storageGet(key) {
  return new Promise(resolve => {
    chrome.storage.session.get(key, result => resolve(result));
  });
}

function storageSet(value) {
  return new Promise(resolve => {
    chrome.storage.session.set(value, () => resolve());
  });
}

function storageRemove(key) {
  return new Promise(resolve => {
    chrome.storage.session.remove(key, () => resolve());
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
  url.searchParams.delete("tid");
  url.searchParams.append("tid", tenantId);
  return url.toString();
}

function getState(rawUrl, activeTenant) {
  let url;

  try {
    url = new URL(rawUrl);
  } catch {
    return { state: "gray", reason: "Invalid URL", supported: false };
  }

  if (!isSupportedAdminUrl(url)) {
    return {
      state: "gray",
      reason: "Not a supported Microsoft admin site",
      supported: false,
      currentTid: null
    };
  }

  if (!activeTenant?.tenantId) {
    return {
      state: "gray",
      reason: "No active tenant set",
      supported: true,
      currentTid: getCurrentTid(rawUrl)
    };
  }

  const currentTid = getCurrentTid(rawUrl);

  if (!currentTid) {
    return {
      state: "red",
      reason: "No tenant ID found in URL",
      supported: true,
      currentTid: null
    };
  }

  if (normalize(currentTid) === normalize(activeTenant.tenantId)) {
    return {
      state: "green",
      reason: "Correct tenant",
      supported: true,
      currentTid
    };
  }

  return {
    state: "red",
    reason: "Different tenant ID found in URL",
    supported: true,
    currentTid
  };
}

async function getActiveTenant() {
  const result = await storageGet("activeTenant");
  return result.activeTenant || null;
}

async function setIcon(tabId, state) {
  const iconPath = {
    green: "icons/green.png",
    red: "icons/red.png",
    gray: "icons/gray.png"
  }[state] || "icons/gray.png";

  chrome.action.setIcon({
    tabId,
    path: {
      "16": iconPath,
      "32": iconPath,
      "48": iconPath,
      "128": iconPath
    }
  });
}

async function updateTabState(tabId, rawUrl) {
  const activeTenant = await getActiveTenant();
  const result = getState(rawUrl, activeTenant);

  await setIcon(tabId, result.state);

  chrome.action.setTitle({
    tabId,
    title: [
      "TID Guard",
      activeTenant?.tenantLabel ? `Active: ${activeTenant.tenantLabel}` : "Active: none",
      activeTenant?.tenantId ? `TID: ${activeTenant.tenantId}` : null,
      `Status: ${result.reason}`
    ].filter(Boolean).join("\n")
  });
}

async function updateCurrentTabState() {
  chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
    const tab = tabs[0];
    if (tab?.id && tab?.url) {
      await updateTabState(tab.id, tab.url);
    }
  });
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.url) {
    await updateTabState(tabId, changeInfo.url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  chrome.tabs.get(tabId, async tab => {
    if (tab?.url) {
      await updateTabState(tabId, tab.url);
    }
  });
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
      await updateCurrentTabState();
      sendResponse({ success: true });
    });

    return true;
  }

  if (message.action === "clearActiveTenant") {
    storageRemove("activeTenant").then(async () => {
      await updateCurrentTabState();
      sendResponse({ success: true });
    });

    return true;
  }

  if (message.action === "getStatus") {
    chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
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
    chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
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
      chrome.tabs.update(tab.id, { url: newUrl });

      sendResponse({
        success: true,
        newUrl
      });
    });

    return true;
  }
});