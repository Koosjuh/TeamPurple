# Quick guide: how to perform this AI code and security review

**Disclaimer** Vibe coding is great, it let's people with no coding experience make a product and give reality to a vision. However do not assume vibe coding is secure or that your product is secure. We intent to give you some working handles. This review and this blog does not replace a real human/developer in the loop.

This workflow is meant for people who built something with AI and want a serious review before going further. It is not a replacement for a real developer and security review for a production system. However before you continue vibe coding your product please take security into account. The earlier you implement these frameworks and mindset into your product the easier it is to finally deploy to production (with a real developer).

## What is being checked

The review combines four sources:

1. **Google code review principles**
   This checks code quality and maintainability first.
   It looks at correctness, design, complexity, tests, naming, comments, consistency, and maintainability.

2. **NIST SSDF**
   This checks whether secure software development practices exist, such as secret handling, dependency management, code review, testing, and vulnerability response.

3. **OWASP**
   This checks common web application security controls and risks, such as authentication, authorization, input validation, XSS, SQL injection, CSRF, headers, secrets, logging, and supply chain risk.

4. **HAR runtime evidence**
   This checks what the website actually does in the browser, such as headers, cookies, transport security, CORS, login behavior, data exposure, and third-party calls.

## What you need to provide

- The website source code zipped. As a back up you can provide your git hub url but most AI can not fetch that data
- The JSON schema. Filled in with your website details
- A HAR file from your browser

## How to capture the HAR file

1. Open the website in your browser.
2. Press **F12** to open DevTools.
3. Open the **Network** tab.
4. Enable recording.
5. Perform the important actions on the website:
   - open the homepage
   - browse public pages
   - log in if login exists
   - log out
   - submit forms
   - trigger a failed login
   - use authenticated pages
   - perform admin actions if they exist
   - upload a file if uploads exist
   - Basically use all features you want to test
6. Export the Network log as a **HAR** file.
   - Depending on the browser this can be Save As HAR FILE, Export HAR File
   - Double check your HAR File in notepad to see if there is DATA there
7. Upload that HAR file to the AI together with the repository zip and filled in JSON schema.

## Review order

The AI should review in this order:

1. Enumerate every file in the repository
2. Perform code review per relevant file
3. Perform security review per relevant file
4. Review the HAR per user action
5. Compare code, runtime, and declared controls
6. Produce one HTML report

## What the output should look like

The final output should be a single HTML report that includes:

- Executive summary
- Repository coverage summary
- Full file inventory
- Per-file code review
- Per-file security review
- HAR review by action
- Correlation and mismatches
- Top findings
- Critical mistakes
- Remediation priority
- Assumptions and unknowns

The report should contain clickable links so the user can inspect the file, line, or runtime behavior themselves.

## Important limitation

This helps a lot, but it is still an AI-assisted review. If the project is going to be used seriously, exposed to the internet, or will handle real users or sensitive data, a real developer should take over and apply these security principles properly. This is no replacement for a REAL pentest, a REAL developer. If you are going in production with out a real human in the loop, that is at your own risk. This guide/review serves as a base, it's not the final product.
