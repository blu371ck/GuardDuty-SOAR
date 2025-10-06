import importlib
import json
import logging
import os
from pathlib import Path

from aws_lambda_powertools.utilities.typing import LambdaContext

from guardduty_soar.config import get_config
from guardduty_soar.engine import Engine
from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import LambdaEvent, Response


def load_playbooks():
    """
    Dynamically finds and imports all Python playbook files within the 'playbooks'
    directory and its subdirectories.
    """
    # Start the search from the 'guardduty_soar' package directory
    package_dir = os.path.dirname(__file__)
    playbooks_root = os.path.join(package_dir, "playbooks")

    if not os.path.isdir(playbooks_root):
        logger.critical(
            f"Playbooks directory not found at '{playbooks_root}'. No playbooks loaded."
        )
        return

    # Walk through the playbooks directory
    for root, _, files in os.walk(playbooks_root):
        for filename in files:
            if filename.endswith(".py") and not filename.startswith("__"):
                # Construct the full absolute Python import path
                # e.g., /path/to/src/guardduty_soar/playbooks/ec2/instance_compromise.py
                full_path = os.path.join(root, filename)

                # Make the path relative to the 'src' directory's parent
                # e.g., guardduty_soar/playbooks/ec2/instance_compromise.py
                rel_path = os.path.relpath(
                    full_path, os.path.join(package_dir, os.pardir)
                )

                # Convert file path to Python's dot notation
                # e.g., guardduty_soar.playbooks.ec2.instance_compromise
                module_name = os.path.splitext(rel_path.replace(os.sep, "."))[0]

                try:
                    importlib.import_module(module_name)
                except ImportError as e:
                    logger.error(
                        f"Failed to import playbook module {module_name}: {e}."
                    )

    logger.info("Playbook modules loaded and registered.")


def setup_logging():
    """
    Configures the root logger based on the level specified in gd.cfg.
    """
    config = get_config()
    app_log_level_str = config.log_level
    boto_log_level_str = config.boto_log_level

    # Convert the string level (e.g., "INFO") to a logging constant (e.g., logging.INFO)
    app_log_level = getattr(logging, app_log_level_str, logging.INFO)

    # Using force=True to override any default handlers and ensure our format is used.
    logging.basicConfig(
        level=app_log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )
    logging.getLogger("main").info(f"Logging level is set to {app_log_level_str}.")
    boto_log_level = getattr(logging, boto_log_level_str, logging.WARNING)
    logging.getLogger("boto3").setLevel(boto_log_level)
    logging.getLogger("botocore").setLevel(boto_log_level)
    logging.getLogger("urllib3").setLevel(boto_log_level)
    logging.getLogger("main").info(
        f"AWS SDK (boto3) logging level set to {boto_log_level_str}."
    )


# Configure logging as the very first step.
setup_logging()
logger = logging.getLogger("main")

# Load playbooks once when the lambda container starts (cold start), speeding up
# warm invocations later. This may be refactored into part of the engines class.
# With the idea that we should be able to determine and load only the necessary
# playbook. Reducing code footprint and loading times. TODO
load_playbooks()


def main(event: LambdaEvent, context: LambdaContext) -> Response:
    """
    Main Lambda handler function.

    Parameters:
        event: LambdaEvent, containing the lambda function event data as well as
            embedded GuardDuty findings.
        context: Lambda's runtime context.
    Returns:
        status: Dict containing status and message.
    """
    logger.info("Lambda starting up.")

    try:
        # Get the singleton config instance we then inject it into
        # the engine.
        config = get_config()

        # Instantiate the Engine class to parse the event JSON data.
        engine = Engine(event["detail"], config)

        # Lookup the required playbook based on the GuardDuty event type.
        engine.handle_finding()

    except PlaybookActionFailedError as e:
        logger.error(f"A playbook action failed, halting execution: {e}.")
        return {"statusCode": 500, "message": f"Internal playbook error: {e}"}

    except (ValueError, KeyError) as e:
        logger.error(f"Failed to process finding due to bad input: {e}")
        return {"statusCode": 400, "message": str(e)}

    logger.info("Successfully processed GuardDuty finding.")
    return {"statusCode": 200, "message": "GuardDuty finding successfully processed."}
