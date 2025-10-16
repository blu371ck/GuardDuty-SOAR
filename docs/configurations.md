# ⚙️ Configurations

Configurations are the primary mechanism for customizing the behavior of GuardDuty-SOAR. They allow you to enable or disable specific actions, set parameters for playbooks, and configure notifications, all without altering the source code.

#### Toggling Optional and Destructive Actions

Many actions, particularly those that are potentially destructive (e.g., terminating an EC2 instance), are controlled by boolean (`True`/`False`) parameters in the configuration.

Setting one of these parameters to `False` ensures that the corresponding action or functionality will be gracefully skipped during a playbook's execution. This design ensures that no assumptions are made about your organization's security policies, giving you full control over the application's response.

#### Understanding Configuration Precedence

The application loads settings from three sources in a specific order of priority. A setting from a higher-priority source will always override a setting from a lower-priority source.

The order of precedence is:

1. Environment Variables (Highest Priority): Values set as environment variables (e.g., in the Lambda configuration or loaded from a local `.env` file).
2. `gd.cfg` File: Values defined in the `gd.cfg` file located in the project root. This provides the baseline configuration for the application.
3. Hardcoded Defaults (Lowest Priority): Fallback values defined directly in the application code for essential parameters if they are not specified anywhere else.

!!! note
    We do utilize some hard-coded default values. For instance, we have a quarantine action, that isolates an IAM principal with a deny all policy. Instead of asking for a custom deny-all policy from the end-user, we explicitly define the use of AWS's managed `AWSDenyAll` policy.

#### Configuration in Production

While the application can be configured using the `gd.cfg` file, the recommended best practice for production deployments on AWS Lambda is to use environment variables. This decouples your configuration from the code artifact, making it more secure and easier to manage across different environments (e.g., development, staging, production).

When setting environment variables for your Lambda function, the naming convention is as follows:

* Take the parameter name from the `gd.cfg` file.
* Prefix it with `GD_`.
* Convert the entire string to uppercase.

For example, the `log_level` parameter under the `[General]` section in `gd.cfg` becomes the environment variable `GD_LOG_LEVEL`.

!!! note
    This is the exact same naming convention used in `.env` for test configurations. So, if your in doubt of what the key would be, please refer to the `.env.example` file provided in the repository.
