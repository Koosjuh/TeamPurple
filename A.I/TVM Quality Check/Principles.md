1. Purpose & Scope
These principles define how a TVM report must be validated in the following areas:

Document structure & required chapters
Typography & heading hierarchy
Table structure, consistency, and completeness
Important topics marked with “!”
Internal MDR note detection (must not appear)
Technical correctness (non‑hallucinating)
Final readiness verdict

These rules apply to all TVM Analysis Reports delivered to MDR customers.
Copilot or any reviewer must operate in read‑only mode:
No rewriting, no adding content, no improving text — only analysis and deviation reporting.

2. Strict Anti‑Hallucination Policy
To eliminate incorrect assumptions or invented content:
2.1 Copilot must NEVER:

Invent Microsoft URLs
Invent product names, features, or Secure Score actions
Invent MDR processes or recommendations
Invent vulnerabilities, exposure scores, or CA policies
Infer tenant configuration not explicitly inside the document

2.2 Allowed Microsoft sources
Only URLs explicitly present in the report may be referenced.
If a validation would require a Microsoft link that is not present in the document, Copilot must state:

“No Microsoft link present for this item. Cannot cross‑validate without hallucinating.”

This makes hallucination structurally impossible.

3. Required TVM Report Structure
A correct TVM report must contain the following top‑level chapters (Heading 1):


Document Information

Versions
Reviewers
Distribution
Classification



Introduction


Microsoft Secure Score


Identity Protect – Cloud


Identity Protect – On‑Premise


Device Protect


Office Protect


Application Protect


(Optional) Azure Protect


3.1 What must be validated

All required chapters are present
The order matches the standard sequence
No missing or duplicate top-level chapters
No misplaced content where sections are merged or nested incorrectly

3.2 Output
Reviewer must report:

Present chapters
Missing chapters
Order deviations


4. Typography & Heading Requirements
4.1 Allowed fonts
Only the following fonts may appear anywhere in the document:

Arial (Body)
Aptos New Arrow

4.2 Normal text

Style: Normal
Size: 11 pt
Font: Arial (Body)

4.3 Heading rules

Heading 1 → Main chapters
Heading 2 / 3 → Subsections
Heading levels must be consistent across all chapters

4.4 Typography issues include:

Normal text formatted as a heading
Headings formatted as Normal text
Heading level inconsistent with peers
Inline color or broken markup (e.g. span style= fragments)
Broken numbering or malformed characters (e.g. 1[!] Conditional Access Rules)

4.5 Required output
For each deviation:

Location → Current text & style → Expected behavior


5. Table Structure & Completeness Checks
TVM reports rely heavily on structured tables. Copilot must validate:
5.1 Header correctness

All tables must have clear, present, non-empty header cells
No placeholder headers such as “-” or empty fields

5.2 Row completeness
Flag:

Empty rows
Placeholder rows
Rows with missing values in mandatory columns

5.3 Key tables requiring special scrutiny

Versions
Reviewers
Distribution
MDR Modules table
Secure Score & category breakdowns
Entra ID recommended actions
MDI posture tables
Device Protect Advanced Features
ASR rules
Office Protect strict recommendations
Email authentication (SPF / DKIM / DMARC) tables
App Governance summaries

5.4 Special MDR Modules table rule
When a module is not checked, at least 75% of such rows must contain meaningful notes, e.g.:

“2 VMs not monitored”
“Storage accounts not onboarded”

Absent notes must be flagged.
5.5 Output
For each deviation:

Table → Issue → Explanation


6. Important Topic Markers (“!”)
Some chapters include “!” to indicate priority discussion topics.
Reviewer must:

Identify all headings containing “!”
Confirm content exists beneath them
Check marker is correctly formatted (no artifacts like 1[!])
Output a list of all chapters with “!” so analysts can validate coverage

Output format:

Heading → Has content? (Yes/No) → Formatting issues?


7. Internal MDR Notes – Critical Errors
Internal guidance must never appear in customer-facing reports.
Examples:

<<< ... >>>
“Internal note MDR”
“remove before sending”
“internal note”
“[MDR ASM Team]”
Any text describing internal workflow instructions

When found, reviewer must mark:

Critical – internal note still present

If none exist:

“No internal MDR notes found.”


8. Technical Correctness Principles
Reviewers must ensure:
8.1 Internal consistency

Actions tables reference existing headings
Section descriptions align with visible data
Terms within the report are used consistently

8.2 Zero external inference
Copilot may only validate against:

Content inside the document
Microsoft URLs explicitly present in the document
Direct statements, tables, and data in the report

8.3 Forbidden validations
Reviewer must NOT:

Pull content from the web
Validate Secure Score accuracy
Validate portal screenshots
Validate version numbers or licensing externally


9. Final Verdict Model
Copilot must conclude with one of:

Ready to send to customer
Minor issues – fix before sending
Not ready – critical issues

Issues to be included in summary:

Internal MDR notes
Missing chapters
Broken typography or heading levels
Multiple fonts or font drift
Major table inconsistencies
Malformed “!” markers
Formatting problems reducing customer readability


10. Reviewer Output Format
Copilot must output the following sections in order:

Structure check
Typography / headings deviations
Table deviations
Important “!” topics
Internal notes check
Overall verdict and key fixes


11. Usage Instruction for Copilot
This standard must be invoked using the following formula:

“According to the TVM Quality Check principles outlined at: <YOUR GITHUB URL>, perform a TVM Quality Review of this document using STANDARD strictness.”

Copilot must then follow this document exactly as written.

And output only in short form what is needed to change. And if this is acceptable to send to the customer.

It is Accectable when there are no internal MDR notes present and the typography is consistent and all tables are filled in. If it's acceptable but there are still improvements, list these.
