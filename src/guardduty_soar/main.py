import importlib
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from aws_lambda_powertools.utilities.typing import LambdaContext

from guardduty_soar.config import get_config
from guardduty_soar.engine import Engine
from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import LambdaEvent, Response


def load_playbooks(package_dir_override: Optional[Path] = None):
    """
    Dynamically finds and imports modules from the built-in 'playbooks'
    and 'plugins' directories within the application package.

    :param package_dir_override: Optional path objects, mainly used in unit testing.
    """
    logger.info("Loading playbook and action modules...")

    def _discover_and_import(root_path: Path, module_prefix: str):
        """
        Walks a directory and imports all found python modules.

        :param root_path: Path object representing the root path.
        :param module_prefix: String representing the modules prefix location.

        :meta private:
        """
        if not root_path.is_dir():
            logger.debug(f"Directory not found, skipping: {root_path}")
            return

        for root, _, files in os.walk(root_path):
            for filename in files:
                if filename.endswith(".py") and not filename.startswith("__"):
                    module_name_parts = [module_prefix]
                    relative_dir = Path(root).relative_to(root_path)
                    if str(relative_dir) != ".":
                        module_name_parts.extend(relative_dir.parts)
                    module_name_parts.append(Path(filename).stem)

                    module_name = ".".join(module_name_parts)
                    try:
                        importlib.import_module(module_name)
                        logger.debug(f"Successfully imported module: {module_name}")
                    except ImportError as e:
                        logger.error(f"Failed to import module {module_name}: {e}")

    # Use the override if provided for testing, otherwise calculate the real path
    package_dir = package_dir_override or Path(__file__).parent

    # 1. Load built-in playbooks
    _discover_and_import(package_dir / "playbooks", "guardduty_soar.playbooks")

    # 2. Load custom plugins
    plugins_dir = package_dir / "plugins"
    _discover_and_import(plugins_dir / "actions", "guardduty_soar.plugins.actions")
    _discover_and_import(plugins_dir / "playbooks", "guardduty_soar.plugins.playbooks")

    logger.info("Playbook modules loaded and registered.")


def setup_logging():
    """
    This function sets up the entire logging infrastructure of the application.
    It allows end-users to over-ride the verbosity level in the configurations. It
    is also responsible for modifying the logging level of Boto3, which is strictly
    utilized for adding API level debugging. It is strongly suggested to keep
    boto3 logging at WARNING unless you are needed to debug, as its very verbose.
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
# playbook. Reducing code footprint and loading times.
load_playbooks()


def handler(event: LambdaEvent, context: LambdaContext) -> Response:
    """
    The main lambda handler function. Invoked by EventBridge when a GuardDuty
    finding event is emitted.

    :param event: a LambdaEvent object containing the full JSON passed to
        an invoked Lambda function. The GuardDutyEvent object is a nested
        object within this parent object.
    :param context: not used directly, but is the LambdaContext passed
        during Lambda function invocation.
    :return: A Response object that is a dictionary with two keys (status and details).
    """
    logger.info("Lambda starting up.")

    try:
        # Get the singleton config instance we then inject it into
        # the engine.
        config = get_config()

        # Validate finding is not an ignored finding
        if event["detail"]["Type"] in config.ignored_findings:
            logger.info(
                f"Finding type: {event["detail"]["Type"]} explicitly ignored in configuration."
            )
            return {
                "statusCode": 200,
                "message": f"Finding Type: {event["detail"]["Type"]} explicitly ignored in configuration.",
            }

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
