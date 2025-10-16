from typing import Any, Dict, List, Literal, Optional, TypedDict


class Response(TypedDict):
    """
    A model of the Lambda functions response for
    better control.
    """

    statusCode: int
    message: str


class GuardDutyEvent(TypedDict):
    """
    A model of the GuardDuty event that is nested within
    the LambdaEvent when the Lambda function is invoked.
    """

    AccountId: str
    Arn: str
    CreatedAt: str
    Description: str
    Id: str
    Partition: str
    Region: str
    Resource: Dict[str, Any]
    SchemaVersion: str
    Service: Dict[str, Any]
    Severity: int
    Title: str
    Type: str
    UpdatedAt: str


# We declare this model differently because of the improper syntax errors
# that would be generated for `detail-type`.
LambdaEvent = TypedDict(
    "LambdaEvent",
    {
        "version": str,
        "id": str,
        "detail-type": str,
        "source": str,
        "account": str,
        "time": str,
        "region": str,
        "resources": List[Any],
        "detail": GuardDutyEvent,
    },
)


class EnrichedEC2Finding(TypedDict):
    """
    This model specifically models the enriched data structure of the
    playbooks actions. It holds all the extra information we go after
    during a playbook execution, to ensure end-user analyst do not need
    to perform additional actions on their part to find information about
    the objects in question.
    """

    guardduty_finding: GuardDutyEvent
    instance_metadata: Dict[str, Any]


class EnrichedS3Finding(TypedDict):
    """
    This model specifically models the enriched data structure of S3-related
    playbook actions. It holds all the extra information gathered about the S3
    bucket(s) in question.
    """

    guardduty_finding: GuardDutyEvent
    bucket_details: List[Dict[str, Any]]


class ActionResponse(TypedDict):
    """
    This model is utilized for type checking the responses of Actions. Every
    action needs to return a status and some details. The details can be
    customized based on the information gathered, however the status has to be
    a literal value that we can check for, or anticipate.
    """

    status: Literal["success", "error", "skipped"]
    details: Any


class ActionResult(ActionResponse):
    """
    Extends ActionResponse to include the name of the action that was run.
    This is used for building the summary report in notifications.
    """

    action_name: str


class PlaybookResult(TypedDict):
    """
    Models the standardized return type for all playbook 'run' methods,
    replacing the more complex tuple. Every playbook has an inherited run
    method that invokes the pre-determined Actions (as steps). This model
    is designed to make that response uniform and predictable.
    """

    action_results: List[ActionResult]
    enriched_data: Optional[Dict[str, Any]]
