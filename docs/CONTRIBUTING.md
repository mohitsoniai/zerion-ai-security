# WADE AI v2 - Contributing Guide

Thank you for your interest in contributing to WADE AI v2! We welcome developers, researchers, and security experts to help us build a safer browser experience.

---

## 🚦 Guidelines & Code Quality Standards

To maintain code health and a professional portfolio standard, this project enforces formatting, linting, and commit rules.

### 1. Code Formatting & Linting

Before submitting a pull request, ensure your code complies with formatting rules:

- **JavaScript:** Checked using **ESLint** and formatted using **Prettier** (2-space indents).
- **Python:** Follows **PEP-8** styles (4-space indents).
- Run formatting locally:
  ```bash
  npm run format
  npm run lint
  ```

---

## 📝 Commit Guidelines (Conventional Commits)

We use **Commitlint** and **Husky** to enforce clear, semantic commit messages. Every commit message must match the Conventional Commits format:

`type(scope): description`

### Allowed Types

- **`feat`**: A new feature (e.g., `feat(extension): add dashboard dark mode toggle`).
- **`fix`**: A bug fix (e.g., `fix(backend): handle whois socket timeout exceptions`).
- **`docs`**: Documentation adjustments (e.g., `docs(api): add curl query examples`).
- **`style`**: White-space, formatting, semicolons (no code logic changes).
- **`refactor`**: Reorganizing structure (e.g., `refactor(backend): clean class definitions`).
- **`test`**: Adding or refactoring tests.
- **`chore`**: Dependency updates, build changes, package.json files.

---

## 🌿 Git Branching Model

1. **`main`**: Production-ready branch. Do not commit directly to `main`.
2. **Feature Branches**: Branch out from `main` using descriptive names:
   - `feature/your-feature-name`
   - `bugfix/issue-description`
3. Submit a **Pull Request (PR)** targeting the `main` branch. Ensure:
   - The backend code passes syntax compilation (`python -m py_compile backend/app.py`).
   - ESLint and Prettier report zero errors.
   - Your commit history is clean and follows Conventional Commits.
