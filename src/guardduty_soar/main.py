import importlib
import json
import logging
import os

from aws_lambda_powertools.utilities.typing import LambdaContext

from guardduty_soar.engine import Engine
from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import LambdaEvent, Response


def load_playbooks():
    """
    Dynamically finds and imports all Python playbook files within the 'playbooks'
    directory and its subdirectories.
    """
    playbook_root = "src/guardduty_soar/playbooks"
    if not os.path.isdir(playbook_root):
        logger.warning(
            f"Playbook directory not found at '{playbook_root}'. No playbooks loaded."
        )
        return

    # os.walk will traverse the directory tree.
    for root, dirs, files in os.walk(playbook_root):
        for filename in files:
            if filename.endswith(".py") and not filename.startswith("__"):
                # Construct the full module path for importlib
                # e.g., 'src/guardduty_soar/playbooks/ec2/instance_compromise.py'
                # becomes 'guardduty_soar.playbooks.ec2.instance_compromise'
                relative_path = os.path.join(root, filename)
                module_path = relative_path.replace(os.sep, ".")[:-3]  # a/b.py -> a.b
                # We need to remove the 'src.' prefix for the import to work correctly
                # as 'src' is our python path root.
                import_path = module_path.replace("src.", "")

                try:
                    importlib.import_module(import_path)
                except ImportError as e:
                    logger.error(f"Failed to import playbook module {import_path}: {e}")

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
        event: LambdaEvent, containing the lambda function event data as well as
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

    except PlaybookActionFailedError as e:
        logger.critical(f"A playbook action failed, halting execution: {e}.")
        return {"statusCode": 500, "message": f"Internal playbook error: {e}"}

    except (ValueError, KeyError) as e:
        logger.error(f"Failed to process finding due to bad input: {e}")
        return {"statusCode": 400, "message": str(e)}

    logger.info("Successfully processed GuardDuty finding.")
    return {"statusCode": 200, "message": "GuardDuty finding successfully processed."}
