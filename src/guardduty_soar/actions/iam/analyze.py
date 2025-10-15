import logging
from typing import Any, Dict, List

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class AnalyzePermissionsAction(BaseAction):
    """
    An action to analyze IAM policies for overly permissive rules.
    """

    def _normalize_statements(
        self, policy_document: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Handles cases where 'Statement' is a single dict instead of a list."""
        statements = policy_document.get("Statement", [])
        if isinstance(statements, dict):
            return [statements]
        return statements

    def _check_statement(self, statement: Dict[str, Any]) -> List[str]:
        """Checks a single policy statement for risks."""
        risks: List[str] = []

        # Deny policies are not security risks.
        if statement.get("Effect") != "Allow":
            return risks

        actions = statement.get("Action", [])
        if not isinstance(actions, list):
            actions = [actions]

        resources = statement.get("Resource", [])
        if not isinstance(resources, list):
            resources = [resources]

        # Check for wildcard expressions
        is_wildcard_action = any(action == "*" for action in actions)
        is_wildcard_resource = any(resource == "*" for resource in resources)

        if is_wildcard_action and is_wildcard_resource:
            risks.append("Allows all actions ('*') on all resources ('*').")

        # Check for other risky action patterns
        risky_patterns = ["iam:*", "ec2:*", "s3:*"]
        for action in actions:
            if action in risky_patterns and is_wildcard_resource:
                risks.append(f"Allows '{action}' on all resources ('*').")

        return risks

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        """
        Analyzes attached and inline policies from a principal's details.
        """

        if not self.config.analyze_iam_permissions:
            logger.warning("IAM analysis is disabled in the configuration.")
            return {
                "status": "skipped",
                "details": "IAM permission analysis is disabled in config.",
            }

        principal_policies = kwargs.get("principal_policies")
        if not principal_policies:
            return {
                "status": "error",
                "details": "Required 'principal_policies' were not provided.",
            }

        logger.info("Analyzing IAM policies for overly permissive rules.")
        all_risks = {}

        logger.info("Normalizing policies attached to IAM identity.")
        # Analyze attached policies
        for policy in principal_policies.get("attached_policies", []):
            policy_name = policy.get("PolicyName", "UnknownPolicy")
            policy_risks = []
            statements = self._normalize_statements(policy.get("PolicyDocument", {}))

            for stmt in statements:
                policy_risks.extend(self._check_statement(stmt))

            if policy_risks:
                all_risks[f"AttachedPolicy: {policy_name}"] = policy_risks

        logger.info("Normalizing inline policies on IAM identity.")
        # Analyze inline policies
        for name, doc in principal_policies.get("inline_policies", {}).items():
            policy_risks = []
            statements = self._normalize_statements(doc)

            for stmt in statements:
                policy_risks.extend(self._check_statement(stmt))

            if policy_risks:
                all_risks[f"InlinePolicy: {name}"] = policy_risks

        if not all_risks:
            logger.info("No overly permissive rules found in IAM policies.")
        else:
            logger.warning(f"Found {len(all_risks)} potential IAM policy risks.")

        return {"status": "success", "details": {"risks_found": all_risks}}
