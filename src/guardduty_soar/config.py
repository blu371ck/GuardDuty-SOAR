import configparser
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional


@dataclass(frozen=True)
class AppConfig:
    """A frozen dataclass that holds all application configuration."""

    log_level: str
    boto_log_level: str
    ignored_findings: List[str]
    snapshot_description_prefix: str
    allow_terminate: bool
    allow_remove_public_access: bool
    allow_ses: bool
    registered_email_address: Optional[str]
    allow_sns: bool
    sns_topic_arn: Optional[str]
    cloudtrail_history_max_results: int
    analyze_iam_permissions: bool
    # Add other config attributes here as they come up (Don't forget to add them below as well)


# This function acts as a "factory" for the AppConfig object.
@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """
    Parses config files and returns a cached, singleton instance of the AppConfig.
    """
    CLOUDTRAIL_MAX = 50
    CLOUDTRAIL_MIN = 1
    CLOUDTRAIL_DEFAULT = 25

    # Environment-aware path calculation for gd.cfg
    if "LAMBDA_TASK_ROOT" in os.environ:
        # In AWS Lambda, the root is the task root
        project_root = os.environ["LAMBDA_TASK_ROOT"]
    else:
        project_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
    config_file = os.path.join(project_root, "gd.cfg")

    config = configparser.ConfigParser()

    if os.path.exists(config_file):
        config.read(config_file)

    raw_ct_results = (
        os.environ.get("GD_CLOUDTRAIL_HISTORY_MAX_RESULTS")
        or config.get("IAM", "cloudtrail_history_max_results", fallback=None)
        or str(CLOUDTRAIL_DEFAULT)
    )

    try:
        validated_ct_results = int(raw_ct_results)
        # Use max() and min() to force the constraint
        validated_ct_results = max(
            CLOUDTRAIL_MIN, min(validated_ct_results, CLOUDTRAIL_MAX)
        )
    except (ValueError, TypeError):
        # If the value is not a valid integer default to default
        validated_ct_results = CLOUDTRAIL_DEFAULT

    # Helper to parse a list from the config
    def get_list(section, key):
        raw_value = os.environ.get(f"GD_{key.upper()}") or config.get(
            section, key, fallback=""
        )
        return [line.strip() for line in raw_value.split("\n") if line.strip()]

    snapshot_prefix = os.environ.get("GD_SNAPSHOT_DESCRIPTION_PREFIX")
    if not snapshot_prefix:
        snapshot_prefix = config.get(
            "EC2", "snapshot_description_prefix", fallback="GD-SOAR-Snapshot-"
        )

    # Create the AppConfig object by reading each value safely
    return AppConfig(
        ignored_findings=get_list("General", "ignored_findings"),
        snapshot_description_prefix=snapshot_prefix,
        boto_log_level=os.environ.get("GD_BOTO_LOG_LEVEL")
        or config.get("General", "boto_log_level", fallback="WARNING").upper(),
        log_level=os.environ.get("GD_LOG_LEVEL")
        or config.get("General", "log_level", fallback="INFO").upper(),
        cloudtrail_history_max_results=validated_ct_results,
        allow_terminate=os.environ.get("GD_ALLOW_TERMINATE") is not None
        or config.getboolean("EC2", "allow_terminate", fallback=True),
        allow_remove_public_access=os.environ.get("GD_REMOVE_PUBLIC_ACCESS") is not None
        or config.getboolean("EC2", "allow_remove_public_access", fallback=False),
        allow_ses=os.environ.get("GD_ALLOW_SES") is not None
        or config.getboolean("Notifications", "allow_ses", fallback=False),
        registered_email_address=os.environ.get("GD_REGISTERED_EMAIL_ADDRESS")
        or config.get("Notifications", "registered_email_address", fallback=None),
        allow_sns=os.environ.get("GD_ALLOW_SNS") is not None
        or config.getboolean("Notifications", "allow_sns", fallback=False),
        sns_topic_arn=os.environ.get("GD_SNS_TOPIC_ARN")
        or config.get("Notifications", "sns_topic_arn", fallback=None),
        analyze_iam_permissions=os.environ.get("GD_ANALYZE_IAM_PERMISSIONS") is not None
        or config.getboolean("IAM", "analyze_iam_permissions", fallback=True),
    )
