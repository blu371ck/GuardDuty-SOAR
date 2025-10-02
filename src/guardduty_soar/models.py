from typing import Any, Dict, List, Literal, TypedDict


class ActionResponse(TypedDict):
    """
    A standardized dictionary structure for the return value of all Action
    classes.
    """

    status: Literal["success", "error"]
    details: str


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
