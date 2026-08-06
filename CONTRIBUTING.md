# Contributing to Zerion AI Security

First off, thank you for considering contributing to **Zerion AI Security**! 🎉

 Zerion AI Security is an open-source, AI-powered browser security and threat intelligence platform. Contributions from developers, security researchers, and enthusiasts help make web browsing safer for everyone.

Whether you are fixing a bug, adding a feature, improving documentation, or reporting an issue, your help is warmly welcomed.

---

## 📋 Table of Contents

- [Code of Conduct](#-code-of-conduct)
- [Getting Started & Development Setup](#-getting-started--development-setup)
- [Coding Standards](#-coding-standards)
- [Commit Message Convention](#-commit-message-convention)
- [Pull Request Process](#-pull-request-process)
- [Reporting Bugs](#-reporting-bugs)
- [Requesting Features](#-requesting-features)
- [Documentation Guidelines](#-documentation-guidelines)
- [Code Review Process](#-code-review-process)

---

## 📜 Code of Conduct

We are committed to providing a welcoming, inclusive, and respectful community for all contributors. Please maintain professional communication in all issues, pull requests, and discussions.

---

## 💻 Getting Started & Development Setup

### 1. Fork & Clone

Fork the repository on GitHub and clone your fork locally:

```bash
git clone https://github.com/YOUR-USERNAME/zerion-ai-security.git
cd zerion-ai-security
```

Add the upstream remote:

```bash
git remote add upstream https://github.com/mohitsoniai/zerion-ai-security.git
```

### 2. Environment Setup

Create a virtual environment and install Python dependencies:

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt
```

Create a `.env` file in the root directory:

```env
GEMINI_API_KEY=your_development_key
ZERION_API_KEY=zerion_secret_key_v2
JWT_SECRET=dev_jwt_secret_32_bytes_long_key_string
```

### 3. Run Backend Server

```bash
python -m backend.app
```

The backend server runs locally on **`http://localhost:7860`**.

### 4. Load Unpacked Chrome Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable **Developer Mode** (top-right toggle)
3. Click **Load unpacked** and select the `extension/` folder in your repository workspace.

---

## 🎨 Coding Standards

To maintain high technical quality and consistency, please follow these guidelines:

### Python (Backend)
- Follow **PEP 8** style guidelines.
- Use explicit type hints for function signatures (`def scan_url(url: str) -> dict:`).
- Use `async/await` non-blocking patterns for external I/O and database operations.
- Handle exceptions explicitly; avoid naked `except:` blocks.
- Preserve structured JSON logging (`backend/utils/logger.py`).

### JavaScript (Chrome Extension & Dashboard)
- Use modern **ES6+** syntax (`const`/`let`, arrow functions, `async`/`await`).
- Comply strictly with Chrome Extension **Manifest V3** Content Security Policy (CSP).
- Do not import remote external scripts directly in extension HTML files (use local vendor bundles in `extension/libs/`).
- Sanitize all DOM inputs to prevent Cross-Site Scripting (XSS).

### HTML / CSS
- Maintain dark cyber UI aesthetics (`#0a0b10` background, `#00d4ff` cyan accent, glassmorphism overlays).
- Keep CSS modular and avoid arbitrary pixel magic numbers.

---

## 📝 Commit Message Convention

We follow the **Conventional Commits** specification:

```
<type>(<scope>): <short summary>

[optional body]
```

### Allowed Types:
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style/formatting (no logic changes)
- `refactor`: Code restructuring without changing behavior
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks, dependencies, workflow updates

### Examples:
```bash
git commit -m "feat(api): add WHOIS registrar verification endpoint"
git commit -m "fix(extension): resolve tab listener race condition on page navigation"
git commit -m "docs(readme): add docker compose deployment instructions"
```

---

## 🔀 Pull Request Process

1. **Create a Feature Branch**:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. **Keep Branch Updated**:
   Rebase against `upstream/main` before opening your PR:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```
3. **Verify Locally**:
   - Ensure the FastAPI backend starts without errors.
   - Test the Chrome Extension popup and background script.
4. **Submit Pull Request**:
   - Open a PR against the `main` branch of `mohitsoniai/zerion-ai-security`.
   - Provide a clear summary of what changed and why.
   - Reference any related open issues (e.g., `Fixes #42`).

---

## 🐛 Reporting Bugs

Before creating a bug report, please search existing [GitHub Issues](https://github.com/mohitsoniai/zerion-ai-security/issues) to avoid duplicates.

When filing a bug report, include:
- **Operating System** & **Browser Version** (e.g., Windows 11, Chrome 125).
- **Steps to Reproduce** the bug.
- **Expected Behavior** vs **Actual Behavior**.
- **Console Logs** or **Backend Stack Traces** (if available).

> 🛑 **Note**: For security vulnerabilities, please refer to our [SECURITY.md](SECURITY.md) for private disclosure instructions.

---

## 💡 Requesting Features

We welcome ideas for new features! When submitting a feature request:
- Explain the **use case** and why it provides value to users.
- Outline any proposed API design or UI mockups.
- Be open to community feedback and technical discussion.

---

## 📚 Documentation Guidelines

Documentation is as important as code. When adding new endpoints or features:
- Update [README.md](README.md) if user workflows change.
- Keep inline Python docstrings up to date.
- Update documentation files in `docs/` for architecture or deployment changes.

---

## 🔍 Code Review Process

- All submitted Pull Requests will be reviewed by project maintainers.
- Reviewers may suggest code style updates, performance optimizations, or edge-case handling.
- Once approved and CI checks pass, your PR will be merged into `main`.
- You will be credited in the repository release notes!

---

<p align="center">
  Thank you for contributing to <b>Zerion AI Security</b>! 🛡️
</p>
