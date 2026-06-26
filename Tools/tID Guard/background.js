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

function getState(rawUrl, configuredTenantId) {
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

  const supported = isSupportedAdminUrl(url);

  if (!supported) {
    return {
      state: "gray",
      reason: "Not a supported Microsoft admin site",
      currentTid: null,
      supported: false
    };
  }

  if (!configuredTenantId) {
    return {
      state: "gray",
      reason: "No tenant configured",
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

  if (normalize(currentTid) === normalize(configuredTenantId)) {
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

async function getConfig() {
  return await chrome.storage.sync.get(["tenantId", "tenantName"]);
}

async function setIcon(tabId, state) {
  const iconPath = {
    green: "icons/green.png",
    red: "icons/red.png",
    gray: "icons/gray.png"
  }[state] || "icons/gray.png";

  await chrome.action.setIcon({
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
  const { tenantId, tenantName } = await getConfig();
  const result = getState(rawUrl, tenantId);

  await setIcon(tabId, result.state);

  const titleParts = [
    "TID Guard",
    tenantName ? `Configured: ${tenantName}` : null,
    tenantId ? `TID: ${tenantId}` : null,
    `Status: ${result.reason}`
  ].filter(Boolean);

  await chrome.action.setTitle({
    tabId,
    title: titleParts.join("\n")
  });
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    await updateTabState(tabId, changeInfo.url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);

  if (tab.url) {
    await updateTabState(tabId, tab.url);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getStatus") {
    chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
      const tab = tabs[0];
      const { tenantId, tenantName } = await getConfig();

      if (!tab?.url) {
        sendResponse({
          state: "gray",
          reason: "No active tab",
          tenantId,
          tenantName
        });
        return;
      }

      const result = getState(tab.url, tenantId);

      sendResponse({
        ...result,
        tenantId,
        tenantName,
        currentUrl: tab.url,
        hostname: new URL(tab.url).hostname
      });
    });

    return true;
  }

  if (message.action === "applyTid") {
    chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
      const tab = tabs[0];
      const { tenantId } = await getConfig();

      if (!tab?.id || !tab?.url || !tenantId) {
        sendResponse({
          success: false,
          reason: "Missing active tab or configured tenant ID"
        });
        return;
      }

      const newUrl = setTid(tab.url, tenantId);

      await chrome.tabs.update(tab.id, { url: newUrl });

      sendResponse({
        success: true,
        newUrl
      });
    });

    return true;
  }
});
