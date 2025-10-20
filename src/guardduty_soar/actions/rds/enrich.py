# actions/rds/enrich.py

import logging
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError
from pydantic import ValidationError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent
from guardduty_soar.schemas import RdsEnrichmentData, RDSInstanceDetails

logger = logging.getLogger(__name__)


class EnrichRdsFindingAction(BaseAction):
    """
    An action to enrich RDS instance details from a GuardDuty finding. It gathers
    configuration details, cluster info, security groups, tags, and recent events.

    :param session: A boto3 Session object to build clients with.
    :param config: The Application's configurations.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.rds_client = self.session.client("rds")
        self.ec2_client = self.session.client("ec2")

    def _get_enrichment_data(self, db_instance_identifier: str) -> Dict[str, Any]:
        """
        Helper to fetch all enrichment data for a single RDS instance.

        :param db_instance_identifier: The DB instance identifier to gather information on.
        :return: A dictionary object that is used to create the RdsEnrichmentData model.
        """
        data: Dict[str, Any] = {"db_instance_identifier": db_instance_identifier}

        # 1. Get Core Instance Details (and check for cluster association)
        try:
            instance_info = self.rds_client.describe_db_instances(
                DBInstanceIdentifier=db_instance_identifier
            )["DBInstances"][0]
            data["instance_details"] = instance_info

            # 2. Get Cluster Details (if applicable)
            cluster_id = instance_info.get("DBClusterIdentifier")
            if cluster_id:
                cluster_info = self.rds_client.describe_db_clusters(
                    DBClusterIdentifier=cluster_id
                )["DBClusters"][0]
                data["cluster_details"] = cluster_info

            # 3. Get Security Group Rules
            sg_ids = [
                sg["VpcSecurityGroupId"]
                for sg in instance_info.get("VpcSecurityGroups", [])
            ]
            if sg_ids:
                data["security_groups"] = self.ec2_client.describe_security_groups(
                    GroupIds=sg_ids
                )["SecurityGroups"]

            # 4. Get Tags
            db_arn = instance_info.get("DBInstanceArn")
            if db_arn:
                data["tags"] = self.rds_client.list_tags_for_resource(
                    ResourceName=db_arn
                ).get("TagList", [])

            # 5. Get Recent Events
            data["recent_events"] = self.rds_client.describe_events(
                SourceIdentifier=db_instance_identifier, SourceType="db-instance"
            ).get("Events", [])

        except ClientError as e:
            # A broad catch-all for boto errors during enrichment
            logger.error(f"Failed to enrich RDS instance {db_instance_identifier}: {e}")
        except Exception as e:
            logger.error(f"An unknown error occurred: {e}.")

        return data

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        enriched_instances: List[Dict[str, Any]] = []
        errors: List[str] = []

        resource_data = event.get("Resource", {})
        if resource_data.get("ResourceType") != "DBInstance":
            return {
                "status": "skipped",
                "details": "Resource type is not DBInstance.",
            }

        instance_details_list = resource_data.get("RdsDbInstanceDetails", [])
        if not instance_details_list:
            return {
                "status": "skipped",
                "details": "No RDS instances listed in this finding.",
            }

        for instance_data in instance_details_list:
            try:
                model = RDSInstanceDetails(**instance_data, ResourceType="DBInstance")
                db_instance_identifier = model.db_instance_identifier
                if not db_instance_identifier:
                    continue

                logger.warning(
                    f"ACTION: Enriching details for RDS instance: {db_instance_identifier}"
                )
                raw_enriched_data = self._get_enrichment_data(db_instance_identifier)

                # Validate the final data structure against the Pydantic model
                validated_data = RdsEnrichmentData(**raw_enriched_data).model_dump(
                    exclude_none=True
                )
                enriched_instances.append(validated_data)

            except ValidationError as e:
                error_detail = f"Failed to validate enriched data for '{instance_data.get('DbInstanceIdentifier', 'Unknown')}': {e}"
                logger.error(error_detail)
                errors.append(error_detail)
            except Exception as e:
                error_detail = f"An unknown error occurred while enriching '{instance_data.get('DbInstanceIdentifier', 'Unknown')}': {e}"
                logger.error(error_detail)
                errors.append(error_detail)

        if errors:
            return {
                "status": "error",
                "details": f"Completed with {len(errors)} error(s). Enriched: {len(enriched_instances)} instance(s).",
            }

        return {
            "status": "success",
            "details": enriched_instances,
        }
