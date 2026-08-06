# Security Policy

**Zerion AI Security** takes the security of our platform, users, and ecosystem very seriously. We appreciate the work of security researchers, community members, and organizations who help us maintain a safe and reliable cybersecurity platform.

This policy outlines how to report vulnerabilities, our response timelines, disclosure policies, and recommended security best practices.

---

## 🛡️ Supported Versions

We actively release security patches and updates for the following versions of Zerion AI Security:

| Version | Supported | Security Patch Support | Status |
| :--- | :---: | :--- | :--- |
| `v1.0.x` | ✅ Yes | Full active security support | Current Stable |
| `< 1.0.0` | ❌ No | Deprecated / Beta releases | End of Life (EOL) |

*We strongly recommend all users stay updated with the latest release on the [`main`](https://github.com/mohitsoniai/zerion-ai-security) branch.*

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability or potential threat in Zerion AI Security (including the FastAPI backend, Chrome Extension, OSINT integrations, or web dashboard), please report it to us **privately** before public disclosure.

> **⚠️ DO NOT open public GitHub Issues or Pull Requests for security vulnerabilities.**

### Private Submission Channels

Please submit vulnerability reports via one of the following methods:

1. **GitHub Private Vulnerability Reporting** (Preferred):
   - Navigate to the [Security Tab](https://github.com/mohitsoniai/zerion-ai-security/security) on GitHub.
   - Click **"Report a vulnerability"** to submit a private report directly to the maintainers.

2. **Direct Email**:
   - Email: **security@zerion.ai** (or contact **[Mohit Swarnkar](https://github.com/mohitsoniai)** directly via GitHub).
   - Subject Line: `[SECURITY VULNERABILITY] <Component Name> - <Short Summary>`

---

## 📝 What to Include in Your Report

To help us investigate and resolve the issue quickly, please include as much of the following information as possible:

- **Type of issue**: (e.g., XSS, SQLi, Remote Code Execution, Authentication Bypass, API Token Leak, Extension Privilege Escalation).
- **Affected component(s)**: (`backend/`, `extension/`, `database/`, Docker, CI/CD).
- **Step-by-step reproduction instructions**: Proof of concept (PoC) code or requests.
- **Impact assessment**: Potential consequences of exploitation.
- **Suggested remediation**: (Optional) Recommended code patches or configuration changes.

---

## ⏱️ Response & Remediation Timeline

We adhere to a strict SLA timeline to ensure timely resolution of reported issues:

| Phase | Target SLA | Description |
| :--- | :--- | :--- |
| **Initial Acknowledgment** | Within **24 hours** | We acknowledge receipt of your vulnerability report. |
| **Triage & Severity Assessment** | Within **72 hours** | We confirm reproducibility and assign a CVSS severity score. |
| **Patch Development & Testing** | Within **7–14 days** | We develop, test, and verify the security patch. |
| **Public Advisory & Release** | Within **30 days** | Security advisory published alongside fixed release. |

---

## 🤝 Responsible Disclosure Policy

Zerion AI Security follows **Coordinated Vulnerability Disclosure (CVD)** guidelines.

### We Ask That Researchers:

- Give us reasonable time to investigate and patch the vulnerability before making details public.
- Avoid accessing, modifying, or destroying user data during testing.
- Test only against your own local instances or dedicated test environments (`localhost:7860`).
- Do not perform Denial of Service (DoS/DDoS) attacks against production APIs or third-party threat feeds.
- Comply with local laws and regulations.

### Our Commitment:

- We will **not** take legal action against researchers who comply with this policy and act in good faith.
- We will acknowledge your contribution in our Security Release Notes (unless you prefer anonymity).
- We will keep you updated throughout the remediation process.

---

## 🔒 Security Best Practices for Deployment

When running Zerion AI Security in production environments, ensure you follow these security precautions:

### 1. API Key Protection
- Never commit `.env` files or API secrets to public version control.
- Ensure `ZERION_API_KEY` and `JWT_SECRET` use cryptographically secure random values (minimum 32 bytes).

### 2. HTTPS & TLS
- In production, always host the FastAPI backend behind a reverse proxy (e.g., Nginx, Caddy, or Cloudflare) configured with TLS 1.3.

### 3. Rate Limiting
- Keep the built-in Token Bucket rate limiter enabled to protect against automated API abuse.

### 4. Chrome Extension Manifest V3 Compliance
- Ensure `extension/libs/` relies exclusively on local static dependencies (like local Leaflet.js) to comply with Chrome Web Store CSP guidelines.

---

## 📧 Contact Information

For security inquiries, vulnerability reports, or security-related questions:

- **Maintainer**: Mohit Swarnkar
- **Role**: Full Stack Developer & AI Engineer
- **GitHub**: [@mohitsoniai](https://github.com/mohitsoniai)
- **Project Repository**: [https://github.com/mohitsoniai/zerion-ai-security](https://github.com/mohitsoniai/zerion-ai-security)

---

<p align="center">
  <sub>Thank you for keeping Zerion AI Security and our community safe! 🛡️</sub>
</p>
