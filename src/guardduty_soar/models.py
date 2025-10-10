from typing import Any, Dict, List, Literal, Optional, TypedDict


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

    status: Literal["success", "error", "skipped"]
    details: Any


class MalwareScanDetail(TypedDict):
    """
    Models the 'detail' object of a GuardDuty Malware Scan status change event.
    """

    scanId: str
    scanStatus: Literal["COMPLETED", "FAILED"]
    resourceArn: str
    threats: List[Dict[str, Any]]


class MalwareScanEvent(TypedDict):
    """
    The top-level event for a GuardDuty Malware Scan status change.
    """

    version: str
    id: str
    detail_type: Literal["GuardDuty Malware Protection Scan status change"]
    source: Literal["aws.guardduty"]
    account: str
    time: str
    region: str
    resources: List[str]
    detail: MalwareScanDetail


class ActionResult(ActionResponse):
    """
    Extends ActionResponse to include the name of the action that was run.
    This is used for building the summary report in notifications.
    """

    action_name: str


class PlaybookResult(TypedDict):
    """
    Models the standardized return type for all playbook 'run' methods,
    replacing the more complex tuple.
    """

    action_results: List[ActionResult]
    enriched_data: Optional[Dict[str, Any]]
