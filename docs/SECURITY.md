# Zerion AI v2 - Security Policy

This document outlines the security architecture, data handling safeguards, and reporting guidelines for Zerion AI v2.

---

## 🛡️ Core Security Architecture

Zerion AI v2 is built to inspect threats out-of-band and intervene directly within the client browser session.

### 1. Client-Side XSS Neutralization

Zerion AI's injected content script monitors the DOM via `MutationObserver` and dynamically intercepts elements attempting inline execution:

- Elements containing `onclick`, `onmouseover`, or `href="javascript:..."` are tagged.
- Inline script links are neutralized by swapping their `href` target with `#` and caching the original payload in a `data-zerion-blocked-href` property. This prevents instant drive-by execution while maintaining page load aesthetics.

### 2. Context-Aware Navigation Interceptor

- Zerion AI uses Chrome's `webNavigation.onBeforeNavigate` API to catch requests in flight.
- If a domain is flagged as dangerous (>75% risk), the extension interrupts the navigation event, redirects the frame to the secure local resource `blocked.html`, and severs connection.

### 3. Phishing Deception Countermeasures

- To counter phishing credential harvesting, the extension contains hooks (`FETCH_JUNK_DATA` handler) to generate realistic but fake admin credentials to poison inputs or foil attackers attempting visual scraping.

---

## 🔒 Data Privacy & Sovereignty

- **Zero Local File Exposure:** Zerion AI does not scan or upload local desktop files. Download alerts are raised strictly based on matches of file extensions (e.g. `.exe`, `.vbs`, `.scr`) and warn the user before opening.
- **Metadata Anonymization:** URL scans submitted to the backend API exclude session identifiers, cookies, headers, or query parameters.
- **No Cache Leaks:** The Tranco whitelist database lookup happens entirely locally within the extension's local chrome storage, preventing search metadata from leaking to third-party endpoints.

---

## 🐛 Reporting a Vulnerability

If you discover a security vulnerability in this project, please notify us immediately:

1. **Email:** Submit a report describing the vulnerability, including step-by-step reproduction steps, to the repository maintainer.
2. **Responsible Disclosure:** We request that you do not release details of a vulnerability publicly until we have patched it.
3. **Response Timeline:** We aim to investigate and respond to security issues within **48 hours** and provide a patch within **7 days**.
