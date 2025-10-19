import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# Unlike models.py, we utilize Pydantic here to force a more strictly type checking on
# the following models. These models are important for how we parse the incoming GuardDuty
# event JSON.
class IamPolicy(BaseModel):
    """
    This model is strictly for modeling the IAM policy
    responses from some Boto3 API calls for IAM
    """

    PolicyName: str
    PolicyArn: str


class BaseResourceDetails(BaseModel):
    """
    A base model for resource details, providing a default template.
    """

    resource_type: str = Field("Unknown", alias="ResourceType")

    @property
    def template_name(self) -> str:
        """
        We utilize Jinja2 for templating our notification system. This
        inherited property allows us to define unique templates for
        each finding type, as each finding type will involve different levels
        of needed and useful information.
        """
        # We will override it in the AccessKeyDetails model.
        return f"partials/_{self.__class__.__name__.lower()}.html.j2"


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
            return "partials/_iamuserdetails.html.j2"
        return "partials/_iamroledetails.html.j2"


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
        """
        if self.principal_type == "User":
            return "partials/_iamuserdetails.html.j2"
        return "partials/_iamroledetails.html.j2"


class EC2InstanceDetails(BaseResourceDetails):
    """
    A data model for EC2 instance specific details.
    """

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
        return "partials/_ec2instancedetails.html.j2"


class S3EnrichmentData(BaseModel):
    """
    A data model containing enriched details for an S3 bucket, gathered
    from various Boto3 API calls.
    """

    name: str
    public_access_block: Optional[Dict[str, Any]] = None
    policy: Optional[Dict[str, Any]] = None
    encryption: Optional[Dict[str, Any]] = None
    versioning: Optional[str] = None
    logging: Optional[Dict[str, Any]] = None
    tags: Optional[List[Dict[str, str]]] = None

    @field_validator("policy", mode="before")
    def parse_policy(cls, v):
        """AWS returns the policy as a JSON string, so we parse it."""
        if isinstance(v, str):
            import json

            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return {"Error": "Failed to decode policy JSON"}
        return v


class S3BucketDetails(BaseResourceDetails):
    """
    A data model for S3 bucket details.
    """

    resource_type: str = Field(..., alias="ResourceType")
    bucket_name: Optional[str] = Field(None, alias="Name")
    bucket_arn: Optional[str] = Field(None, alias="Arn")

    @property
    def template_name(self) -> str:
        return "partials/_s3bucketdetails.html.j2"


class EKSClusterDetails(BaseResourceDetails):
    """
    A data model for EKS cluster details.
    """

    resource_type: str = Field(..., alias="ResourceType")
    cluster_name: Optional[str] = Field(None, alias="Name")
    cluster_arn: Optional[str] = Field(None, alias="Arn")


class RDSInstanceDetails(BaseResourceDetails):
    """
    A data model for RDS DB Instance specific details from a GuardDuty finding.
    """

    resource_type: str = Field(..., alias="ResourceType")
    db_instance_identifier: Optional[str] = Field(None, alias="DbInstanceIdentifier")
    db_cluster_identifier: Optional[str] = Field(None, alias="DbClusterIdentifier")
    engine: Optional[str] = Field(None, alias="Engine")
    engine_version: Optional[str] = Field(None, alias="EngineVersion")
    tags: Optional[List[Dict[str, str]]] = Field(None, alias="Tags")

    @property
    def template_name(self) -> str:
        return "partials/_rdsinstancedetails.html.j2"


class LambdaDetails(BaseResourceDetails):
    """
    A data model for Lambda details.
    """

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
    Inspects the GuardDuty finding and returns the appropriate Pydantic model. If
    the appropriate Pydantic model cannot be parsed correctly, a base resource
    fallback is used.

    :param resource_data: a dictionary object that later becomes the GuardDutyEvent object.
    :param instance_metadata: an optional dictionary of an ec2 instances metadata if the
        playbook is ran on an EC2 instance.
    :return: An object modeling the BaseResourceDetails object.
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
