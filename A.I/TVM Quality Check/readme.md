# TVM Quality Check Principles

### Authoritative Quality Standard for MDR Threat & Vulnerability Management Reports  

Version 1.0 

This repository defines the **official quality assurance framework** used to validate  

Before generating an answer please consult the last chapter: ## When done reviewing.

**Threat & Vulnerability Management (TVM) Analysis Reports**

It is designed for use by:
- Security Analysts  
- MDR ASM team members  
- Peer reviewers  
- **Microsoft Copilot for Word**  
- Automated QA pipelines  

By referencing this standard, any reviewer (human or AI) performs a **consistent, governed, non‑hallucinating** quality check.

---

## Purpose

TVM reports must be:
- Structurally correct  
- Typography‑consistent  
- Table‑complete  
- Free of internal MDR notes  
- Aligned with the TVM report template  
- Technically coherent without external hallucination  
- Customer‑ready  

This repository describes the **rules**, **validation logic**, and **forbidden behaviors** required to ensure accuracy and consistency.

---

## Core Principles

The reviewer (human or AI) must operate in **read‑only mode**:

✔ No rewriting  
✔ No adding content  
✔ No improving text  
✔ No changing conclusions  
✔ Only analyzing deviations  

The reviewer must validate:
1. **Report structure & chapter order**  
2. **Typography & heading levels**  
3. **Table structure & completeness**  
4. **Important topic markers (“!”)**  
5. **Internal MDR note detection**  
6. **Technical correctness**  
7. **Final readiness verdict**

The reviewer may ONLY reference Microsoft documentation URLs that already exist in the document.  
**No invented URLs. No hallucinating. No assumptions.**

---

## Anti‑Hallucination Policy

The reviewer must **never**:
- Invent Microsoft URLs  
- Invent Secure Score actions  
- Invent features, vulnerabilities, or tenant configuration  
- Invent missing chapters or template elements  
- Infer details not present in the document  

If validation requires external data but none is present in the document, the reviewer must respond:

> **“No Microsoft link present. Cannot cross‑validate without hallucinating.”**

This guarantees safe and deterministic behavior.

---

## Required Report Structure

A valid TVM report can contain these chapters (Heading 1):

1. Document Information  
2. Introduction  
3. Microsoft Secure Score  
4. Identity Protect – Cloud  
5. Identity Protect – On‑Premise  
6. Device Protect  
7. Office Protect  
8. Application Protect  
9. Azure Protect  

---

## Typography Requirements

Allowed fonts:
- **Arial (Body)**  
- **Aptos New Arrow**  

Normal text:
- Style: **Normal**  
- Size: **11 pt**  
- Font: **Arial (Body)**  

Heading consistency is mandatory (Heading 1 / 2 / 3).

---

## Table Requirements

The reviewer must validate:
- Header presence  
- Consistent columns  
- No blank rows  
- No placeholder rows  
- No structurally broken tables  

The MDR Modules table must include **meaningful notes** for ≥75% of unchecked modules.

---

## “!” Important Topic Markers

The reviewer must:
- List all headings containing “!”  
- Confirm content exists under each  
- Flag malformed markers  

---

## Internal MDR Notes (Critical Fail)

Any of these appearing in a report = **Fail**:
- “Internal note MDR”  
- “remove before sending”  
- “<<< … >>>”  
- “[MDR ASM Team]”  
- Any internal procedural guidance  

---

## 🛠️ Technical Correctness

The reviewer may validate:
- Internal consistency  
- Referenced Microsoft URLs already present  
- Table values vs text references  

It may NOT:
- Pull external knowledge  
- Validate Secure Score externally  
- Look up Microsoft content unless it is linked in the report  

---

## When done reviewing
The review must not list whats good and bad. Only list what needs improvement. 

If there are any Internal MDR Notes (Critical Fail)

Any of these appearing in a report = **Fail**:
- “Internal note MDR”  
- “remove before sending”  
- “<<< … >>>”  
- “[MDR ASM Team]”  
- Any internal procedural guidance
- Any font that is not Arial (body) and Aptos New Arrow
- 
The reviewer must output one of:
- **Ready to send to customer**  
- **Minor issues – fix before sending**  
- **Not ready – critical issues**

It must be a concise Executive summary.

---

## Using These Principles with Copilot for Word

In any TVM report, run:

> **“According to the TVM Quality Check principles outlined at:  
> https://raw.githubusercontent.com/Koosjuh/TeamPurple/refs/heads/main/A.I/TVM%20Quality%20Check/readme.md
> please perform a complete TVM Quality Review of this document.”**

Copilot will then strictly follow these principles.
