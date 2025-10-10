import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class IamPolicy(BaseModel):
    PolicyName: str
    PolicyArn: str


class BaseResourceDetails(BaseModel):
    """A base model for resource details, providing a default template."""

    resource_type: str = Field("Unknown", alias="ResourceType")

    @property
    def template_name(self) -> str:
        return f"partials/_{self.__class__.__name__.lower()}.md.j2"


class IamPrincipalInfo(BaseModel):
    """Base model for IAM user or role details."""

    details: Dict[str, Any]
    attached_policies: List[IamPolicy]
    inline_policies: Dict[str, Any]

    @property
    def template_name(self) -> str:
        # A property to dynamically select the right template
        if "UserId" in self.details:  # Users have a UserId, Roles have a RoleId
            return "partials/_iamuserdetails.md.j2"
        return "partials/_iamroledetails.md.j2"


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


class AccessKeyDetails(BaseResourceDetails):
    resource_type: str = Field(..., alias="ResourceType")
    access_key_id: Optional[str] = Field(None, alias="AccessKeyId")
    principal_id: Optional[str] = Field(None, alias="PrincipalId")
    user_name: Optional[str] = Field(None, alias="UserName")


class S3BucketDetails(BaseResourceDetails):
    resource_type: str = Field(..., alias="ResourceType")
    bucket_name: Optional[str] = Field(None, alias="Name")
    bucket_arn: Optional[str] = Field(None, alias="Arn")


class EKSClusterDetails(BaseResourceDetails):
    resource_type: str = Field(..., alias="ResourceType")
    cluster_name: Optional[str] = Field(None, alias="Name")
    cluster_arn: Optional[str] = Field(None, alias="Arn")


class RDSInstanceDetails(BaseResourceDetails):
    resource_type: str = Field(..., alias="ResourceType")
    db_instance_identifier: Optional[str] = Field(None, alias="DbInstanceIdentifier")
    db_cluster_identifier: Optional[str] = Field(None, alias="DbClusterIdentifier")
    engine: Optional[str] = Field(None, alias="Engine")


class LambdaDetails(BaseResourceDetails):
    resource_type: str = Field(..., alias="ResourceType")
    function_name: Optional[str] = Field(None, alias="FunctionName")
    function_arn: Optional[str] = Field(None, alias="FunctionArn")


def map_resource_to_model(
    resource_data: dict, instance_metadata: Optional[dict] = None
) -> BaseResourceDetails:
    """
    Inspects the GuardDuty finding and returns the appropriate Pydantic model.
    """
    resource_type = resource_data.get("ResourceType")

    try:
        if resource_type == "Instance":
            details = resource_data.get("InstanceDetails", {})
            if instance_metadata:
                details.update(instance_metadata)
            return EC2InstanceDetails(**details, ResourceType=resource_type)

        elif resource_type == "AccessKey":
            details = resource_data.get("AccessKeyDetails", {})
            return AccessKeyDetails(**details, ResourceType=resource_type)

        elif resource_type == "S3Bucket":
            # S3 details are a list, so we take the first one
            details = resource_data.get("S3BucketDetails", [{}])[0]
            return S3BucketDetails(**details, ResourceType=resource_type)

        elif resource_type == "EKSCluster":
            details = resource_data.get("EksClusterDetails", {})
            return EKSClusterDetails(**details, ResourceType=resource_type)

        elif resource_type == "DBInstance":
            details = resource_data.get("RdsDbInstanceDetails", {})
            return RDSInstanceDetails(**details, ResourceType=resource_type)

        elif resource_type == "Lambda":
            details = resource_data.get("LambdaDetails", {})
            return LambdaDetails(**details, ResourceType=resource_type)

    except Exception as e:
        logger.error(
            f"Failed to map resource type: '{resource_type}': {e}. Falling back."
        )

    return BaseResourceDetails(ResourceType=resource_type or "Unknown")
