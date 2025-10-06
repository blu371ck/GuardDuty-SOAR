import logging
import os
from typing import Any, Dict, Optional, Union, cast

import boto3
import jinja2

from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, EnrichedEC2Finding, GuardDutyEvent
from guardduty_soar.schemas import map_resource_to_model

logger = logging.getLogger(__name__)


class BaseNotificationAction:
    """
    An abstract base class for all notification actions, providing a common
    interface and helper methods for templating with Jinja2.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        """Initializes the action with a boto3 session, app config, and Jinja2."""
        self.session = session
        self.config = config

        # This path navigates up from the relative path of here: /src/guardduty_soar/actions/notifications
        # to the project root and then into the /templates directory.
        package_dir = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        templates_path = os.path.join(package_dir, "templates")
        logging.debug(f"Loaded templates in: {templates_path}.")
        template_loader = jinja2.FileSystemLoader(searchpath=templates_path)
        self.jinja_env = jinja2.Environment(loader=template_loader, autoescape=True)

    def _render_template(self, channel: str, template_name: str, context: dict) -> str:
        """Renders a Jinja2 template for a specific channel."""
        full_template_path = f"{channel}/{template_name}"
        template = self.jinja_env.get_template(full_template_path)
        logging.debug(f"Jinja loaded templates in: {full_template_path}.")
        return template.render(context)

    def _build_template_context(
        self, data: Union[GuardDutyEvent, EnrichedEC2Finding], **kwargs
    ) -> Dict[str, Any]:
        """Creates a structured context dictionary for the templating engine."""
        instance_metadata: Optional[Dict[str, Any]] = None
        finding: GuardDutyEvent
        logger.info("Building template context for messaging.")
        # Use 'cast' to explicitly narrow the type for Mypy or it produces
        # an error.
        if "guardduty_finding" in data:
            enriched_data = cast(EnrichedEC2Finding, data)
            finding = enriched_data["guardduty_finding"]
            instance_metadata = enriched_data.get("instance_metadata")
        else:
            finding = cast(GuardDutyEvent, data)

        resource_details_model = map_resource_to_model(
            finding.get("Resource", {}), instance_metadata=instance_metadata
        )

        return {
            "finding": finding,
            "playbook_name": kwargs.get("playbook_name", "UnknownPlaybook"),
            "resource": resource_details_model,
            "completion_details": kwargs,
        }

    def execute(
        self, data: Union[GuardDutyEvent, EnrichedEC2Finding], **kwargs
    ) -> ActionResponse:
        raise NotImplementedError
