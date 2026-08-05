# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-08-05

### Added

- **Environment Configuration:** Configured `python-dotenv` in `backend/app.py` and provided `.env.example` to manage developer credentials securely.
- **Project Tooling Configurations:** Created `.editorconfig`, `.prettierrc`, `.eslintrc.json`, and `commitlint.config.js` to ensure styling, linting, and Conventional Commits are followed.
- **Modern Git Hook Support:** Added `package.json` specifying ESLint, Prettier, Husky, and Commitlint devDependencies.
- **Comprehensive Documentation:** Added detailed documentation inside `docs/` (`SYSTEM_ARCHITECTURE.md`, `API_DOCUMENTATION.md`, `DEPLOYMENT_GUIDE.md`, `SECURITY.md`, `CONTRIBUTING.md`).
- **Relocation of Core Components:** Moved `backend/`, `extension/`, and `models/` to the root workspace level, streamlining the folder layout for portfolio presentation.

### Changed

- **Backend app.py Refactoring:** PEP-8 style formatting, addition of clean docstrings, type annotations, and improved error handling for WHOIS and SSL queries.
- **Unused Dependencies Cleanup:** Cleaned up Flask references from Python `requirements.txt` which are redundant in a FastAPI server.
- **Deduplication:** Deleted old duplicate `data/malicious_signatures.txt` at the root workspace directory, keeping the primary copy inside `backend/data/`.

---

## [1.0.0] - 2026-07-20

### Added

- **Multimodal AI Analysis:** Dual-model pipeline combining Google Gemini 1.5 and Groq Llama 3.3.
- **Dynamic Threat Intel Feeds:** Sync processing for active malicious links from URLHaus and Phishing.Database.
- **IPS Warning Interceptor:** Block page navigation overlay if a site's threat score exceeds 75%.
- **Heuristic link HUD:** Popup display of age and status warnings on link hover actions.
- **Cyberpunk Command Center:** Interactive HTML dashboard with tilt effects, custom whitelist management, and stats charts.
