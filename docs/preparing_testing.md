# 🧪 Preparing for Testing

This project employs a multi-layered testing strategy managed by `pytest` and `uv`.

---
## Test Categories

| Test Type            | Description                                                                                                                              |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **Unit** | Fast, isolated tests that validate a single component in memory without external dependencies.                                             |
| **Integration** | Verifies individual Actions against live AWS services in isolated, temporary environments. Requires AWS credentials.                      |
| **End-to-End (E2E)** | Simulates a full playbook execution triggered by a mock GuardDuty event, interacting with multiple live AWS services. Requires AWS credentials. |
| **Validation Scenarios** | Terraform scripts that provision infrastructure for live, manual validation of a fully deployed Lambda function.                    |

---
## 1. Initial Setup

All commands should be run from the root of the project directory.

**Environment and Dependencies**

1.  **Create Virtual Environment**: `uv venv`
2.  **Activate Virtual Environment**:
    * PowerShell: `.venv\Scripts\Activate.ps1`
    * macOS/Linux: `source .venv/bin/activate`
3.  **Install All Dependencies**: This installs both production (`requirements.txt`) and development (`requirements-dev.txt`) packages.
    ```bash
    uv pip sync requirements.txt requirements-dev.txt
    ```

**Test Configuration (`.env` file)**

1.  **Create `.env` file**:
    * Windows: `copy .env.example .env`
    * macOS/Linux: `cp .env.example .env`
2.  **Populate `.env` File**: Open the new `.env` file and replace the placeholder values with resources from your AWS test account.

!!! note
    The `.env` file is listed in `.gitignore` and will never be committed to source control.

---
## 2. Running the Tests

Use `uv run` shortcuts to execute different test suites via `pytest` markers.

| Test Suite          | Command                                   | Description                                                     |
| ------------------- | ----------------------------------------- | --------------------------------------------------------------- |
| **Unit Tests** | `uv run pytest -m "not integration and not e2e"` | Runs all fast, local tests that do not require AWS.             |
| **Integration Tests** | `uv run pytest -m "integration"`            | Runs tests for individual Actions against live AWS services.    |
| **E2E Tests** | `uv run pytest -m "e2e"`                    | Runs full playbook simulations against live AWS services.       |

---
## 3. Advanced Test Execution

* **Run a Single File**:
    ```bash
    uv run pytest tests/e2e/test_e2e_ec2_instance_compromise.py
    ```
* **Run a Single Test by Name** (using `-k`):
    ```bash
    uv run pytest -k "test_remove_public_access_integration"
    ```
* **Display Live Logs** (using `-s`):
    ```bash
    uv run pytest -s -m "e2e"
    ```