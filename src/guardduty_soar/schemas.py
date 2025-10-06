import logging
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class BaseResourceDetails(BaseModel):
    """A base model for resource details, providing a default template."""

    resource_type: str = Field("Unknown", alias="ResourceType")

    @property
    def template_name(self) -> str:
        return f"partials/_baseresourcedetails.md.j2"


class EC2InstanceDetails(BaseResourceDetails):
    """A data model for EC2 instance specific details."""

    resource_type: str = Field(..., alias="ResourceType")
    instance_id: str = Field(..., alias="InstanceId")
    public_ip: Optional[str] = None
    vpc_id: Optional[str] = Field(None, alias="VpcId")
    instance_type: Optional[str] = Field(None, alias="InstanceType")
    image_id: Optional[str] = Field(None, alias="ImageId")
    iam_profile_arn: Optional[str] = None
    tags: Optional[List[Dict[str, str]]] = Field(None, alias="Tags")

    @property
    def template_name(self) -> str:
        return f"partials/_ec2instancedetails.md.j2"


def map_resource_to_model(
    resource_data: dict, instance_metadata: Optional[dict] = None
) -> BaseResourceDetails:
    """
    Inspects the GuardDuty finding's resource data and returns the
    appropriate Pydantic model.
    """
    resource_type = resource_data.get("ResourceType")

    # For now, since we are only working with EC2 instances, we define
    # proper resources this way. This code may get extremely long by
    # the time we are finished, so it may need refactoring. TODO
    if resource_type == "Instance":
        try:
            details = resource_data.get("InstanceDetails", {})

            if instance_metadata:
                details.update(instance_metadata)

            details["ResourceType"] = resource_type

            public_ip = None
            if "NetworkInterfaces" in details and details["NetworkInterfaces"]:
                net_interface = details["NetworkInterfaces"][0]
                # Check the top level of the interface first
                public_ip = net_interface.get("PublicIpAddress")
                # If not found, check inside the 'Association' nested dictionary
                if not public_ip and "Association" in net_interface:
                    public_ip = net_interface["Association"].get("PublicIp")

            iam_profile_arn = None
            if instance_metadata and "IamInstanceProfile" in instance_metadata:
                iam_profile_arn = instance_metadata["IamInstanceProfile"].get("Arn")

            return EC2InstanceDetails(
                **details, public_ip=public_ip, iam_profile_arn=iam_profile_arn
            )
        except Exception as e:
            logger.error(f"Failed to map EC2 instance details: {e}. Falling back.")
            return BaseResourceDetails(
                ResourceType=(
                    resource_type if isinstance(resource_type, str) else "Unknown"
                )
            )

    logger.warning(
        f"No specific model mapping for resource type '{resource_type}'. Using base model."
    )
    final_resource_type = resource_type if isinstance(resource_type, str) else "Unknown"
    return BaseResourceDetails(ResourceType=final_resource_type)
