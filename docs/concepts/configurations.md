# ⚙️ Configurations

Configurations are the primary mechanism for customizing the behavior of GuardDuty-SOAR. They allow you to enable or disable specific actions, set parameters for playbooks, and configure notifications, all without altering the source code.

#### Toggling Optional and Destructive Actions

Many actions, particularly those that are potentially destructive (e.g., terminating an EC2 instance), are controlled by boolean (<mark style="color:$primary;">`True`</mark>/<mark style="color:$primary;">`False`</mark>) parameters in the configuration.

Setting one of these parameters to <mark style="color:$primary;">`False`</mark> ensures that the corresponding action or functionality will be gracefully skipped during a playbook's execution. This design ensures that no assumptions are made about your organization's security policies, giving you full control over the application's response.

#### Understanding Configuration Precedence

The application loads settings from three sources in a specific order of priority. A setting from a higher-priority source will always override a setting from a lower-priority source.

The order of precedence is:

1. Environment Variables (Highest Priority): Values set as environment variables (e.g., in the Lambda configuration or loaded from a local <mark style="color:$primary;">`.env`</mark> file).
2. <mark style="color:$primary;">`gd.cfg`</mark> File: Values defined in the <mark style="color:$primary;">`gd.cfg`</mark> file located in the project root. This provides the baseline configuration for the application.
3. Hardcoded Defaults (Lowest Priority): Fallback values defined directly in the application code for essential parameters if they are not specified anywhere else.

{% hint style="info" %}
We do utilize some hard-coded default values. For instance, we have a quarantine action, that isolates an IAM principal with a deny all policy. Instead of asking for a custom deny-all policy from the end-user, we explicitly define the use of AWS's managed <mark style="color:$primary;">`AWSDenyAll`</mark> policy.
{% endhint %}

#### Configuration in Production

While the application can be configured using the <mark style="color:$primary;">`gd.cfg`</mark> file, the recommended best practice for production deployments on AWS Lambda is to use environment variables. This decouples your configuration from the code artifact, making it more secure and easier to manage across different environments (e.g., development, staging, production).

When setting environment variables for your Lambda function, the naming convention is as follows:

* Take the parameter name from the <mark style="color:$primary;">`gd.cfg`</mark> file.
* Prefix it with <mark style="color:$primary;">`GD_`</mark>.
* Convert the entire string to uppercase.

For example, the <mark style="color:$primary;">`log_level`</mark> parameter under the <mark style="color:$primary;">`[General]`</mark> section in <mark style="color:$primary;">`gd.cfg`</mark> becomes the environment variable <mark style="color:$primary;">`GD_LOG_LEVEL`</mark>.

{% hint style="info" %}
This is the exact same naming convention used in <mark style="color:$primary;">`.env`</mark> for test configurations. So, if your in doubt of what the key would be, please refer to the <mark style="color:$primary;">`.env.example`</mark> file provided in the repository.
{% endhint %}
