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
        # This default behavior is the source of the error for AccessKey.
        # We will override it in the AccessKeyDetails model.
        return f"partials/_{self.__class__.__name__.lower()}.md.j2"


class IamPrincipalInfo(BaseModel):
    """
    A container for the ENRICHED details of an IAM user or role,
    designed to be passed to the Jinja templates.
    """

    details: Dict[str, Any]
    attached_policies: List[IamPolicy]
    inline_policies: Dict[str, Any]
    permission_analysis: Optional[Dict[str, Any]] = None

    @property
    def template_name(self) -> str:
        if "UserId" in self.details:
            return "partials/_iamuserdetails.md.j2"
        return "partials/_iamroledetails.md.j2"


class AccessKeyDetails(BaseResourceDetails):
    """
    Models the resource details for an AccessKey finding and intelligently
    identifies the principal to select the correct rendering template.
    """

    resource_type: str = Field(..., alias="ResourceType")
    access_key_id: Optional[str] = Field(None, alias="AccessKeyId")
    principal_id: Optional[str] = Field(None, alias="PrincipalId")
    user_name: Optional[str] = Field(None, alias="UserName")

    @property
    def principal_type(self) -> str:
        """Determines if the principal is a User or a Role based on finding details."""
        if self.user_name:
            return "User"
        # IAM Role principal IDs typically start with 'AROA'. User IDs start with 'AIDA'.
        if self.principal_id and self.principal_id.startswith("AROA"):
            return "Role"
        # Default to Role if we can't be sure, as it's a safe assumption for automation.
        return "Role"

    @property
    def template_name(self) -> str:
        """
        Overrides the base behavior to point to the correct IAM principal template.
        THIS IS THE KEY FIX.
        """
        if self.principal_type == "User":
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
        return "partials/_ec2instancedetails.md.j2"


# --- Other resource models can remain as they were ---
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


# A dictionary to map resource types to their model and the key for details in the finding
RESOURCE_MODEL_MAP = {
    "Instance": (EC2InstanceDetails, "InstanceDetails"),
    "AccessKey": (AccessKeyDetails, "AccessKeyDetails"),
    "S3Bucket": (S3BucketDetails, "S3BucketDetails"),
    "EKSCluster": (EKSClusterDetails, "EksClusterDetails"),
    "DBInstance": (RDSInstanceDetails, "RdsDbInstanceDetails"),
    "Lambda": (LambdaDetails, "LambdaDetails"),
}


def map_resource_to_model(
    resource_data: dict, instance_metadata: Optional[dict] = None
) -> BaseResourceDetails:
    """
    Inspects the GuardDuty finding and returns the appropriate Pydantic model.
    """
    resource_type = resource_data.get("ResourceType", "Unknown")
    if result := RESOURCE_MODEL_MAP.get(resource_type):
        model_class, details_key = result
    else:
        model_class, details_key = (None, None)

    if not model_class:
        logger.warning(
            f"No model mapping for resource type: '{resource_type}'. Falling back."
        )
        return BaseResourceDetails(ResourceType=resource_type or "Unknown")

    try:
        details = resource_data.get(details_key, {})
        if resource_type == "S3Bucket":
            details = details[0] if details else {}
        if resource_type == "Instance" and instance_metadata:
            details.update(instance_metadata)
        return model_class(**details, ResourceType=resource_type)
    except Exception as e:
        logger.error(
            f"Failed to map resource type '{resource_type}': {e}. Falling back."
        )
        return BaseResourceDetails(ResourceType=resource_type or "Unknown")
