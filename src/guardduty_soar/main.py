import importlib
import json
import logging
import os

from aws_lambda_powertools.utilities.typing import LambdaContext

from guardduty_soar.engine import Engine
from guardduty_soar.models import LambdaEvent, Response
from guardduty_soar.playbook_registry import get_playbook_instance


def load_playbooks():
    """Dynamically imports all Python files from the 'playbooks' directory."""
    playbook_dir = "src/guardduty_soar/playbooks"
    if not os.path.isdir(playbook_dir):
        # If the directory doesn't exist, just log a warning and return.
        # This makes the handler more resilient.
        logger.warning(
            f"Playbook directory not found at '{playbook_dir}'. No playbooks loaded."
        )
        return

    for filename in os.listdir(playbook_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            # Construct the full module path for importlib
            module_name = f"guardduty_soar.playbooks.{filename[:-3]}"
            importlib.import_module(module_name)
    logger.info("Playbook modules loaded and registered.")


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("main")

# Load playbooks once when the lambda container starts (cold start), speeding up
# warm invocations later.
load_playbooks()


def main(event: LambdaEvent, context: LambdaContext) -> Response:
    """
    Main Lambda handler function.

    Parameters:
        event: Dict[str, Any] containing the lambda function event data as well as
            embedded GuardDuty findings.
        context: Lambda's runtime context.
    Returns:
        status: Dict containing status and message.
    """
    logger.info("Lambda starting up.")
    try:
        # Instantiate the Engine class to parse the event JSON data.
        engine = Engine(event["detail"])

        # Lookup the required playbook based on the GuardDuty event type.
        engine.handle_finding()

        # If no errors have occurred, we simply return a success message to the caller.
    except (ValueError, KeyError) as e:
        logger.error(f"Failed to process finding: {e}")
        return {"statusCode": 400, "message": str(e)}

    return {"statusCode": 200, "message": "GuardDuty finding successfully processed."}
