import logging
from typing import Dict, List

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class CreateSnapshotAction(BaseAction):
    """
    An action to create EBS snapshots of all volumes attached to a
    compromised EC2 instance for forensic analysis.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.ec2_client = self.session.client("ec2")

    def _get_volume_ids(self, instance_id: str) -> List[str]:
        """
        Describes the EC2 instance to find all attached EBS volume
        IDs. Returns an empty list if none are found or if the instance doesn't
        exist.
        """
        try:
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])

            reservations = response.get("Reservations", [])
            if not reservations:
                return []

            instances = reservations[0].get("Instances", [])
            if not instances:
                return []

            block_devices = instances[0].get("BlockDeviceMappings", [])
            if not block_devices:
                return []

            # Extract the VolumeId from each block device mapping
            return [
                device["Ebs"]["VolumeId"]
                for device in block_devices
                if "Ebs" in device and "VolumeId" in device["Ebs"]
            ]
        except ClientError as e:
            logger.error(
                f"Could not describe instance {instance_id} to get volume IDs: {e}."
            )
            return []

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]

        # Use boto3 call to get the list of EBS volumes.
        volume_ids = self._get_volume_ids(instance_id)

        if not volume_ids:
            details = f"Instance {instance_id} has no EBS volumes attached or could not be described. Skipping snapshot action."
            logger.info(details)
            return {"status": "success", "details": details}

        logger.warning(
            f"ACTION: Creating snapshots for volumes attached to instance {instance_id}: {volume_ids}"
        )

        created_snapshots: List[Dict] = []
        failed_snapshots: List[Dict] = []

        # Handle multiple volumes by iterating through them.
        for volume_id in volume_ids:
            try:
                description_prefix = self.config.snapshot_description_prefix
                description = (
                    f"{description_prefix}InstanceId: {instance_id}, "
                    f"VolumeId: {volume_id}, FindingId: {event['Id']}"
                )

                response = self.ec2_client.create_snapshot(
                    VolumeId=volume_id,
                    Description=description,
                    TagSpecifications=[
                        {
                            "ResourceType": "snapshot",
                            "Tags": [
                                {
                                    "Key": "GuardDuty-SOAR-Finding-ID",
                                    "Value": event["Id"],
                                },
                                {
                                    "Key": "GaurdDuty-SOAR-Source-Instance-ID",
                                    "Value": instance_id,
                                },
                            ],
                        }
                    ],
                )
                snapshot_id = response.get("SnapshotId")
                created_snapshots.append(
                    {"volume_id": volume_id, "snapshot_id": snapshot_id}
                )
                logger.info(
                    f"Successfully initiated snapshot ({snapshot_id}) for volume {volume_id}."
                )

            except ClientError as e:
                error_message = (
                    f"Failed to create snapshot for volume {volume_id}: {e}."
                )
                logger.error(error_message)
                failed_snapshots.append({"volume_id": volume_id, "error": str(e)})

        # Determining final status based on result lists.
        if failed_snapshots:
            final_details = (
                f"Completed snapshots action for {instance_id}. "
                f"Succeeded for volumes: {[s['volume_id'] for s in created_snapshots]}. "
                f"Failed for volumes: {[f['volume_id'] for f in failed_snapshots]}."
            )
            return {"status": "error", "details": final_details}

        final_details = f"Successfully created snapshots for all volumes: {volume_ids}."
        return {"status": "success", "details": final_details}
