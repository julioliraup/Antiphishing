# Contributing to Antiphishing

Thank you for your interest in contributing to the Antiphishing project! We welcome community contributions to help keep this Suricata ruleset updated and effective against malicious threats.

Please review the following guidelines to ensure a smooth contribution process.

---

## 💻 Code Style Guidelines

This project strictly follows the **PEP 8** style guide for Python code. Before submitting any Python script modifications, please ensure your code complies with the following:

*   **Naming:** Use `snake_case` for all function and variable names (e.g., `fetch_phishing_urls`).
*   **Structure:** Keep core logic wrapped inside modular functions and maintain the execution flow within the `main()` function block.
*   **Formatting:** Use 4 spaces per indentation level. Ensure there are exactly two blank lines between top-level function definitions.
*   **Linting:** We highly recommend running `black` or `flake8` on your code before submitting a Pull Request (PR).

---

## 🛡️ Types of Contributions

### 1. Attack Signatures (HTTP/TLS Rules)
If you want to add or modify malicious URL signatures:
*   Ensure your signature follows the standard Suricata ruleset structure used in this project.
*   Keep the variables, metadata formats (`created_et`), and classification types (`social-engineering`) consistent.
*   Submit a **Pull Request (PR)** with your rule additions.

### 2. DNS Rules
If you want to add new malicious domains to the DNS threat feed:
*   Do **not** manually modify the core Python script logic for this.
*   Directly append the new domains to the `phishing.lst` file.
*   Submit a **Pull Request (PR)** with the updated list.

### 3. Documentation
Have ideas to improve this README, add tutorials, or clarify usage?
*   Open an **Issue** outlining your proposed changes.
*   Once discussed, you can submit a PR targeting the specific Markdown files.

### 4. General Feedback & Bug Reports
For any bugs, feature requests, or general rule updates where you cannot provide code directly, please feel free to **open an Issue** in the repository.

---

## ☕ Financial Contributions

Maintaining this project requires active resources, automated testing environments, and software licenses. If you find this ruleset valuable and would like to support its ongoing development and maintenance, financial contributions are greatly appreciated.

You can donate directly via **Pix**:
*   **Pix Key:** `08650081401`

*Your financial support helps cover the necessary software licensing fees and infrastructure costs required to keep the feed alive and accurate.*

---

## 🚀 How to Submit a Pull Request

1. **Fork** the repository.
2. **Clone** your fork locally: `git clone https://github.com...`
3. Create a **new branch** for your feature: `git checkout -b feature/my-new-contribution`
4. **Commit** your changes with clear messages: `git commit -m "Add malicious domain to phishing.lst"`
5. **Push** to your branch: `git push origin feature/my-new-contribution`
6. Open a **Pull Request** against our `main` branch.

