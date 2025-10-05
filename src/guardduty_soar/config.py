import configparser
import os
from functools import lru_cache
from typing import List


class AppConfig:
    """
    A singleton class to handle parsing configuration from both the base
    gd.cfg and a local gd.test.cfg for overrides.
    """

    def __init__(self, config_file="gd.cfg", override_file="gd.test.cfg"):
        project_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )

        base_config_path = os.path.join(project_root, config_file)
        override_config_path = os.path.join(project_root, override_file)

        if not os.path.exists(base_config_path):
            raise FileNotFoundError(
                f"Base configuration file not found at: {base_config_path}"
            )

        self._config = configparser.ConfigParser()

        # Load the base config first
        self._config.read(base_config_path)

        # Now, load the override file if it exists. Its values will take precedence.
        if os.path.exists(override_config_path):
            self._config.read(override_config_path)
            print(f"Loaded integration test overrides from {override_config_path}")

    # --- General Section ---
    @property
    def testing_subnet_id(self) -> str:
        """The subnet ID to use for launching temporary resources in integration tests."""
        return self._config.get("General", "testing_subnet_id", fallback="")

    @property
    def log_level(self) -> str:
        """The log level for the application."""
        level = self._config.get("General", "log_level", fallback="INFO").upper()
        # Ensure the level is a valid one before returning.
        if level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            return "INFO"
        return level

    @property
    def boto_log_level(self) -> str:
        """The log level for the AWS SDK (boto3)."""
        level = self._config.get(
            "General", "boto_log_level", fallback="WARNING"
        ).upper()
        if level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            return "WARNING"
        return level

    # --- EC2 Section ---
    @property
    def ec2_ignored_findings(self) -> List[str]:
        raw_value = self._config.get("EC2", "ignored_findings", fallback="")
        return [line.strip() for line in raw_value.split("\n") if line.strip()]

    @property
    def quarantine_sg_id(self) -> str:
        return self._config.get("EC2", "quarantine_security_group_id")

    @property
    def iam_deny_all_policy_arn(self) -> str:
        return self._config.get("EC2", "iam_deny_all_policy_arn")

    @property
    def snapshot_description_prefix(self) -> str:
        return self._config.get("EC2", "snapshot_description_prefix")

    @property
    def allow_terminate(self) -> bool:
        return self._config.getboolean("EC2", "allow_terminate", fallback=True)

    @property
    def allow_malware_scan(self) -> bool:
        return self._config.getboolean("EC2", "allow_malware_scan", fallback=True)

    # --- Notifications Section ---
    @property
    def allow_ses(self) -> bool:
        return self._config.getboolean("Notifications", "allow_ses", fallback=True)

    @property
    def registered_email_address(self) -> str:
        return self._config.get("Notifications", "registered_email_address")

    @property
    def allow_sns(self) -> bool:
        return self._config.getboolean("Notifications", "allow_sns", fallback=False)

    @property
    def sns_topic_arn(self) -> str:
        return self._config.get("Notifications", "sns_topic_arn")

    @property
    def allow_chatbot(self) -> bool:
        return self._config.getboolean("Notifications", "allow_chatbot", fallback=False)

    @property
    def chatbot_sns_topic_arn(self) -> str:
        return self._config.get("Notifications", "chatbot_sns_topic_arn")

    def __repr__(self) -> str:
        """Provides a developer-friendly string representation of the config."""
        props = ", ".join(
            f"{name}='{getattr(self, name)}'"
            for name in dir(self)
            if isinstance(getattr(type(self), name, None), property)
        )
        return f"AppConfig({props})"


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """Returns a cached, singleton instance of the AppConfig."""
    return AppConfig()
