import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class GetCloudTrailHistoryAction(BaseAction):
    """
    An action to retrieve the recent AWS CloudTrail event history for a specific IAM
    principal ARN identified in a GuardDuty finding. The volume of items retrieved
    is controlled via the configuration `cloudtrail_history_max_results`. The range
    currently is between 1 and 50, with a default value of 25.

    :param session: the Boto3 Session object to make clients with.
    :param config: the Applications configurations.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.cloudtrail_client = self.session.client("cloudtrail")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        """
        Executes the CloudTrail lookup.
        """
        lookup_attributes: List[Dict[str, Any]] = kwargs.get("lookup_attributes", [])

        if not lookup_attributes or not isinstance(lookup_attributes, list):
            return {
                "status": "error",
                "details": "Required 'lookup_attributes' list was not provided or is invalid.",
            }

        principal_identifier = lookup_attributes[0].get("AttributeValue", "Unknown")

        logger.warning(
            f"ACTION: Getting CloudTrail History for principal: {principal_identifier}."
        )

        try:
            max_results = self.config.cloudtrail_history_max_results
            logger.info(f"Max results for CloudTrail history set to {max_results}.")
            response = self.cloudtrail_client.lookup_events(
                LookupAttributes=lookup_attributes,
                MaxResults=max_results,
            )

            events = response.get("Events", [])
            logger.info(f"Successfully found {len(events)} CloudTrail events.")
            return {"status": "success", "details": events}

        except ClientError as e:
            details = f"Failed to get CloudTrail history for {principal_identifier}. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
