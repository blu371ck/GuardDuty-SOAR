# ⚙️ Configurations

Configurations are the primary mechanism for customizing the behavior of GuardDuty-SOAR. They allow you to enable or disable specific actions, set parameters for playbooks, and configure notifications, all without altering the source code.

---
## Toggling Optional and Destructive Actions

Many actions, particularly those that are potentially disruptive (e.g., terminating an EC2 instance), are controlled by boolean (`True`/`False`) parameters in the configuration.

Setting one of these parameters to `False` ensures that the corresponding action will be gracefully skipped during a playbook's execution. This design gives you full control over the application's automated responses.

---
## Understanding Configuration Precedence

The application loads settings from three sources in a specific order of priority. A setting from a higher-priority source will always override one from a lower-priority source.

The order of precedence is:
1.  **Environment Variables (Highest Priority)**: Values set as environment variables (e.g., in the Lambda configuration or loaded from a local `.env` file).
2.  **`gd.cfg` File**: Values defined in the `gd.cfg` file. This provides the baseline configuration for the application.
3.  **Hardcoded Defaults (Lowest Priority)**: Fallback values defined directly in the application code for essential parameters.

!!! note
    We utilize some hard-coded default values for simplicity. For instance, the quarantine action uses AWS's managed `AWSDenyAll` policy by default, rather than requiring you to specify a custom deny-all policy.

---
## Configuration in Production

While the application can be configured using the `gd.cfg` file, the recommended best practice for AWS Lambda is to use **environment variables**. This decouples your configuration from the code artifact, making it more secure and easier to manage across different environments (e.g., development, staging, production).

The naming convention for environment variables is as follows:

* Take the parameter name from the `gd.cfg` file (e.g., `log_level`).
* Prefix it with `GD_`.
* Convert the entire string to uppercase.

This results in the environment variable `GD_LOG_LEVEL`.

!!! note
    This is the exact same naming convention used in the `.env.example` file provided in the repository.