import logging
import time
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
from pydantic import ValidationError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent
from guardduty_soar.schemas import RDSInstanceDetails, RecentRdsQuery

logger = logging.getLogger(__name__)


class GatherRecentQueriesAction(BaseAction):
    """
    An action to gather recent queries for a specific database user by querying
    CloudWatch Logs. This action is dependent on database audit logging being
    enabled and configured to send logs to CloudWatch.

    :param session: A boto3 Session object to build clients with.
    :param config: The Application's configurations.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.logs_client = self.session.client("logs")

    def _get_log_group_name(self, engine: str, db_instance_id: str) -> str:
        """Determines the most likely CloudWatch Log Group name based on engine."""
        # Common log group formats for RDS
        if engine in ["mysql", "mariadb"]:
            # /aws/rds/instance/db-instance-id/audit
            return f"/aws/rds/instance/{db_instance_id}/audit"
        elif engine == "postgres":
            # /aws/rds/instance/db-instance-id/postgresql
            return f"/aws/rds/instance/{db_instance_id}/postgresql"
        elif "sqlserver" in engine:
            # /aws/rds/instance/db-instance-id/audit
            return f"/aws/rds/instance/{db_instance_id}/audit"
        else:
            # Default fallback
            return f"/aws/rds/instance/{db_instance_id}/general"

    def _run_log_query(self, log_group: str, db_user: str) -> List[Dict[str, str]]:
        """
        Executes a CloudWatch Logs Insights query to find recent queries
        by the specified user.
        """
        # This query looks for the username and common SQL commands.
        # It's a best-effort search and may need tuning for specific DB engines.
        query = f"""
        fields @timestamp, @message
        | filter @message like /(?i){db_user}/
        | filter @message like /(?i)(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|EXEC)/
        | sort @timestamp desc
        | limit 25
        """

        try:
            start_query_response = self.logs_client.start_query(
                logGroupName=log_group,
                startTime=int((time.time() - 3600 * 24) * 1000),  # Last 24 hours
                endTime=int(time.time() * 1000),
                queryString=query,
            )
            query_id = start_query_response["queryId"]

            # Poll for query completion
            status = "Running"
            results = []
            timeout = time.time() + 60  # 1 minute timeout
            while status in ["Running", "Scheduled"] and time.time() < timeout:
                time.sleep(2)
                response = self.logs_client.get_query_results(queryId=query_id)
                status = response["status"]
                if status == "Complete":
                    results = response.get("results", [])
                    break

            if status != "Complete":
                logger.warning(f"CloudWatch query {query_id} did not complete in time.")
                return []

            # Format results
            parsed_results = []
            for result_fields in results:
                timestamp = next(
                    (f["value"] for f in result_fields if f["field"] == "@timestamp"),
                    None,
                )
                message = next(
                    (f["value"] for f in result_fields if f["field"] == "@message"), ""
                )
                if timestamp:
                    parsed_results.append({"timestamp": timestamp, "message": message})

            return parsed_results

        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.warning(
                    f"CloudWatch Log Group {log_group} not found. "
                    "Audit logging may be disabled."
                )
            else:
                logger.error(f"Failed to query CloudWatch Logs for {log_group}: {e}")
            return []
        except Exception as e:
            logger.error(f"An unexpected error occurred during log query: {e}")
            return []

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        """
        Running this action requires 'allow_gather_recent_queries' to be True.
        """
        if not self.config.allow_gather_recent_queries:
            return {
                "status": "skipped",
                "details": "Configuration 'allow_gather_recent_queries' is False.",
            }

        all_queries: List[Dict[str, Any]] = []
        errors: List[str] = []

        resource_data = event.get("Resource", {})
        if resource_data.get("ResourceType") != "DBInstance":
            return {"status": "skipped", "details": "Resource type is not DBInstance."}

        instance_details_list = resource_data.get("RdsDbInstanceDetails", [])
        if not instance_details_list:
            return {"status": "skipped", "details": "No RDS instances listed."}

        for instance_data in instance_details_list:
            try:
                model = RDSInstanceDetails(**instance_data, ResourceType="DBInstance")
                db_instance_id = model.db_instance_identifier
                engine = model.engine

                if not model.db_user_details or not model.db_user_details.user:
                    logger.info(
                        f"No DbUserDetails for instance {db_instance_id}, skipping query."
                    )
                    continue

                db_user = model.db_user_details.user

                if not db_instance_id or not engine or not db_user:
                    logger.warning("Missing instance ID, engine, or user. Skipping.")
                    continue

                logger.info(
                    f"Gathering recent queries for user '{db_user}' on instance '{db_instance_id}'"
                )
                log_group = self._get_log_group_name(engine, db_instance_id)

                query_results = self._run_log_query(log_group, db_user)

                for result in query_results:
                    try:
                        query_model = RecentRdsQuery(
                            db_instance_identifier=db_instance_id,
                            db_user=db_user,
                            timestamp=result["timestamp"],
                            query=result["message"],
                        )
                        all_queries.append(query_model.model_dump(exclude_none=True))
                    except ValidationError as e:
                        logger.warning(f"Failed to validate log result: {e}")

            except Exception as e:
                error_detail = f"Failed to gather queries for '{instance_data.get('DbInstanceIdentifier', 'Unknown')}': {e}"
                logger.error(error_detail)
                errors.append(error_detail)

        if errors:
            return {
                "status": "error",
                "details": f"Completed with {len(errors)} error(s). Found {len(all_queries)} queries.",
            }

        return {
            "status": "success",
            "details": all_queries,
        }
