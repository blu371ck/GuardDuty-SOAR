import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, Optional

import boto3
import jinja2

from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent
from guardduty_soar.schemas import BaseResourceDetails, IamPrincipalInfo

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
        self,
        finding: GuardDutyEvent,
        resource: BaseResourceDetails,
        enriched_data: Optional[Dict[str, Any]],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Builds a flat dictionary of context data for the Jinja2 templating engine.
        """
        final_enriched_data = enriched_data

        def json_serial(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")

        # If the enriched data represents an IAM principal, convert the Pydantic
        # model to a dictionary so it can be json-serialized.
        if enriched_data and ("attached_policies" in enriched_data):
            iam_principal_info = IamPrincipalInfo(**enriched_data)
            final_enriched_data = iam_principal_info.model_dump()

        context = {
            "finding": finding,
            "resource": resource,
            "enriched_data": final_enriched_data,
            "enriched_data_json": json.dumps(
                final_enriched_data or {}, default=json_serial, ensure_ascii=False
            ),
        }

        context.update(**kwargs)

        return context

    def execute(self, **kwargs) -> ActionResponse:
        raise NotImplementedError
