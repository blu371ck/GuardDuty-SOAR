import logging
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class GetCloudTrailHistoryAction(BaseAction):
    """
    An action to retrieve the recent AWS CloudTrail event history for
    a specific IAM principal ARN identified in a GuardDuty finding.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.cloudtrail_client = self.session.client("cloudtrail")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        """
        Executes the CloudTrail lookup.
        """
        user_name = kwargs.get("user_name")
        if not user_name:
            return {
                "status": "error",
                "details": "Required 'user_name' was not provided in kwargs.",
            }

        logger.info(f"Getting CloudTrail History for principal: {user_name}.")

        try:
            max_results = self.config.cloudtrail_history_max_results

            response = self.cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "Username", "AttributeValue": user_name}
                ],
                MaxResults=max_results,
            )

            events = response.get("Events", [])
            logger.info(f"Successfully found {len(events)} CloudTrail events.")
            return {"status": "success", "details": events}

        except ClientError as e:
            details = f"Failed to get CloudTrail history for {user_name}. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
