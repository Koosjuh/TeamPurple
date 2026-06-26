# TID Guard

TID Guard is a lightweight browser extension for Microsoft consultants, MSSPs, SOC analysts and system administrators who regularly work across multiple Microsoft Entra ID tenants using guest accounts or Azure Lighthouse.

Its purpose is simple:

**Help prevent administrative actions in the wrong Microsoft tenant.** or **Easily switch to a tenant when clicking links from a document**

Rather than relying on memory or checking the tenant manually, TID Guard provides a visual indicator showing whether the current page matches the tenant you intend to work in.

---

# Features

* Works with Chromium-based browsers

  * Brave
  * Google Chrome
  * Microsoft Edge

* Supports Microsoft administration portals including:

  * Azure Portal
  * Microsoft Entra Admin Center
  * Microsoft 365 Admin Center
  * Microsoft Intune Admin Center
  * Microsoft Defender Portal
  * Microsoft Purview
  * Microsoft Security Portal
  * Exchange Admin Center

* Session-based active tenant

* One-click tenant switching

* Visual status indicator

* No Microsoft Graph permissions required

* No customer information stored permanently

---

# Why TID Guard?

MSSPs and consultants often administer dozens or even hundreds of customer environments.

Although Azure Lighthouse and guest accounts simplify administration, it is still easy to accidentally perform administrative actions in the wrong tenant.

TID Guard acts as a visual safety check before changes are made.

---

# How it works

TID Guard compares:

Configured Active Tenant ID

with

The `tid` parameter in the current Microsoft administration URL.

Depending on the result the extension icon changes automatically.

## Gray

No active tenant configured.

Or

The current website is not a supported Microsoft administration portal.

## Red

A supported Microsoft administration portal is open, but:

* No `tid` is present

or

* The current `tid` does not match the configured active tenant.

## Green

The current page contains the configured Tenant ID.

---

# Session-based design

Unlike many browser extensions, TID Guard intentionally does **not** maintain a permanent list of customer tenants.

The active tenant exists only for the current browser session.

This was a deliberate design decision because many MSSPs work with customer environments that should not be permanently stored inside a browser profile.

When the browser starts again, the active tenant is cleared.

---

# Usage

## Step 1

Open TID Guard.

## Step 2

Paste the Tenant ID.

Optionally enter a descriptive label.

Example:

Customer A Production

## Step 3

Select **Set Active Tenant**.

The extension now monitors supported Microsoft administration portals.

## Step 4

Navigate normally.

The toolbar icon indicates the current status.

## Step 5

If the icon turns red, select:

**Switch current page to active tenant**

TID Guard will:

* Remove any existing `tid`
* Insert the configured Tenant ID
* Reload the current page

---

# Security

TID Guard:

* Does not authenticate to Microsoft Graph
* Does not request Microsoft Graph permissions
* Does not upload data
* Does not maintain a cloud service
* Does not collect telemetry
* Does not permanently store customer tenant information

The extension simply assists with URL-based tenant selection.

---

# Browser Support

* Brave
* Google Chrome
* Microsoft Edge

Firefox support is planned for a future release.

---

## Installation

TID Guard is currently distributed as a source package and can be installed as an unpacked Chromium extension.

### Supported Browsers

* Brave
* Google Chrome
* Microsoft Edge

### 1. Download the repository

Clone the repository:

```bash
git clone https://github.com/<yourusername>/tid-guard.git
```

Or download the repository as a ZIP file from GitHub and extract it.

The folder should contain:

```text
tid-guard/
│
├── manifest.json
├── background.js
├── popup.html
├── popup.js
└── icons/
```

### 2. Open the Extensions page

Depending on your browser:

| Browser        | URL                   |
| -------------- | --------------------- |
| Brave          | `brave://extensions`  |
| Google Chrome  | `chrome://extensions` |
| Microsoft Edge | `edge://extensions`   |

### 3. Enable Developer Mode

Enable **Developer mode** using the toggle in the top-right corner.

### 4. Load the extension

Click **Load unpacked**.

Browse to the extracted **tid-guard** folder and select it.

**Select the folder containing `manifest.json`, not the `icons` folder.**

### 5. Pin the extension

Click the Extensions icon in your browser toolbar and pin **TID Guard** for quick access.

### 6. Configure an active tenant

1. Open TID Guard.
2. Optionally enter a tenant label.
3. Paste the Microsoft Entra Tenant ID.
4. Click **Set active tenant for this browser session**.

The extension will immediately begin monitoring supported Microsoft administration portals.

---

## Updating

After pulling a newer version from GitHub:

1. Replace the existing files.
2. Open your browser's Extensions page.
3. Click **Reload** on TID Guard.

The updated version will be loaded immediately.

---

## Removing

To uninstall TID Guard:

1. Open your browser's Extensions page.
2. Locate **TID Guard**.
3. Click **Remove**.

No customer data or tenant information is retained after removal.


---

# Disclaimer

TID Guard is intended as an operational safety aid.

The extension validates the Tenant ID present in the current URL and provides a visual indication of whether it matches the configured active tenant.

It should not be considered a security boundary or a replacement for verifying the tenant context before performing administrative actions.

Always verify the tenant context before making production changes.
