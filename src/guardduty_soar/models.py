from typing import Any, Dict, List, Literal, TypedDict


class Response(TypedDict):
    """
    Models the Lambda functions response type.
    """

    statusCode: int
    message: str


class GuardDutyEvent(TypedDict):
    """
    Models GuardDuty finding event.
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
    A data structure that combines the original GuardDuty finding with
    rich metadata from the describe_instances call.
    """

    guardduty_finding: GuardDutyEvent
    instance_metadata: Dict[str, Any]


class ActionResponse(TypedDict):
    """
    A standardized dictionary structure for the return value of all Action
    classes.
    """

    status: Literal["success", "error"]
    details: Any
