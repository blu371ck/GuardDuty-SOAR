# Installation

This guide will walk you through setting up the GuardDuty SOAR project for local development and testing.

#### Prerequisites

* Python 3.13+
* [uv](https://github.com/astral-sh/uv): A fast Python package installer and resolver.
* An AWS account with credentials configured locally.
* AWS GuardDuty enabled.
* For EC2, you need VPC flow logs and VPC DNS logs enabled.

#### 1. Clone the Repository

First, clone the project from GitHub to your local machine:

```bash
git clone [https://github.com/your-username/GuardDuty-SOAR.git](https://github.com/your-username/GuardDuty-SOAR.git)
cd GuardDuty-SOAR

```

#### 2. Set Up the Virtual Environment

This project uses `uv` to manage its virtual environment and dependencies. This ensures that the project's packages are isolated from other Python projects on your system.

From the project root directory, run:

```
uv venv

```

This will create a `.venv` directory in your project. The `uv run` command will automatically use this environment without needing manual activation.

#### 3. Install Dependencies

The project is defined as an editable package, with its dependencies listed in `pyproject.toml`. To install everything, run:

```bash
uv pip install -e ".[dev]"

```

* `-e .` installs the project in "editable" mode, meaning changes you make to the source code are immediately reflected.
* `[dev]` installs the optional development dependencies, such as `pytest` and `boto3`.

#### 4. Configure Your Environment

Before running the application or its tests, you need to set up the configuration.

1.  **Copy the Template:** Make a copy of the example configuration file.

    ```bash
    cp gd.cfg.example gd.cfg

    ```
2. **Edit `gd.cfg`:** Open the `gd.cfg` file and fill in the required values, such as your quarantine security group ID and any notification ARNs.

#### 5. Run the Test Suite

To verify that your setup is correct, run the unit test suite. These tests are designed to run without needing live AWS resources.

```bash
uv run pytest -m "not integration"

```

You should see all tests pass. You are now ready to start development!
