import configparser
import os
from functools import lru_cache
from typing import List


class AppConfig:
    """
    A singleton class to handle parsing and providing access to the gd.cfg file.
    """

    def __init__(self, config_file="gd.cfg"):
        project_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        config_path = os.path.join(project_root, config_file)

        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found at: {config_path}")

        self._config = configparser.ConfigParser()
        self._config.read(config_path)

    # --- General Section ---
    @property
    def log_level(self) -> str:
        """The log level for the application."""
        level = self._config.get("General", "log_level", fallback="INFO").upper()
        # Ensure the level is a valid one before returning.
        if level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            return "INFO"
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
