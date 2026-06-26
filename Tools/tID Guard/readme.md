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

# Roadmap

Future ideas include:

* Automatic detection of additional Microsoft administration portals
* Configurable supported domains
* Import/export settings
* Production tenant warnings
* Optional keyboard shortcut for tenant switching
* Optional notifications after switching tenants
* Improved visual indicators

---

# Disclaimer

TID Guard is intended as an operational safety aid.

The extension validates the Tenant ID present in the current URL and provides a visual indication of whether it matches the configured active tenant.

It should not be considered a security boundary or a replacement for verifying the tenant context before performing administrative actions.

Always verify the tenant context before making production changes.
