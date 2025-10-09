import configparser
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import List, Optional

import boto3


@dataclass(frozen=True)
class AppConfig:
    """A frozen dataclass that holds all application configuration."""

    log_level: str
    boto_log_level: str
    aws_region: Optional[str]
    ec2_ignored_findings: List[str]
    quarantine_sg_id: Optional[str]
    iam_deny_all_policy_arn: Optional[str]
    snapshot_description_prefix: str
    allow_terminate: bool
    allow_remove_public_access: bool
    allow_ses: bool
    registered_email_address: Optional[str]
    allow_sns: bool
    sns_topic_arn: Optional[str]
    # Add other config attributes here as they come up (Don't forget to add them below as well)


# This function acts as a "factory" for the AppConfig object.
@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """
    Parses config files and returns a cached, singleton instance of the AppConfig.
    """
    project_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    config_file = os.path.join(project_root, "gd.cfg")

    config = configparser.ConfigParser()

    if os.path.exists(config_file):
        config.read(config_file)

    # Helper to parse a list from the config
    def get_list(section, key):
        raw_value = os.environ.get(f"GD_{key.upper()}") or config.get(
            section, key, fallback=""
        )
        return [line.strip() for line in raw_value.split("\n") if line.strip()]

    snapshot_prefix = os.environ.get("GD_SNAPSHOT_DESC_PREFIX")
    if not snapshot_prefix:
        snapshot_prefix = config.get(
            "EC2", "snapshot_description_prefix", fallback="GD-SOAR-Snapshot-"
        )

    # Create the AppConfig object by reading each value safely
    return AppConfig(
        ec2_ignored_findings=get_list("EC2", "ignored_findings"),
        snapshot_description_prefix=snapshot_prefix,
        boto_log_level=os.environ.get("GD_BOTO_LOG_LEVEL")
        or config.get("General", "boto_log_level", fallback="WARNING").upper(),
        log_level=os.environ.get("GD_LOG_LEVEL")
        or config.get("General", "log_level", fallback="INFO").upper(),
        aws_region=os.environ.get("GD_AWS_REGION")
        or config.get(
            "General", "aws_region", fallback=boto3.Session().region_name or "us-east-1"
        ),
        quarantine_sg_id=os.environ.get("GD_QUARANTINE_SG_ID")
        or config.get("EC2", "quarantine_sg_id", fallback=None),
        iam_deny_all_policy_arn=os.environ.get("GD_IAM_DENY_ALL_POLICY_ARN")
        or config.get("EC2", "iam_deny_all_policy_arn", fallback=None),
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
    )
