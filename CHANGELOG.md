# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNRELEASED]

### Added
- Added configuration: allow_s3_public_block, a boolean value to control whether or not the playbook should attempt to add a block public access policy to an S3 bucket after an exposed finding.
- Added configuration: allow_iam_quarantine, a boolean value to control whether or not the playbook should attempt to add a quarantine AWS Policy on finding IAM principals (right now specifically only on S3 findings).
- Added configuration: iam_deny_all_policy_arn, a string representing a provided ARN for an AWS policy that denies all actions on all resources. This policy is used in quarantine actions, and by default we specify the AWS managed policy AWSDenyAll.
- Updated the IAM action IdentifyIamPrincipalAction, to return both users user name and roles name, as user_name. This is used in S3 playbooks for QuarantineIamPrincipalAction. That action has also been updated with this change.
- Added new action: QuarantineIamPrincipalAction, this action, when enabled, adds the deny-all IAM policy to the IAM principal identified in the GuardDuty finding (right now specifically for S3 playbooks).
  - Added unit testing for this new action.
  - Added integration testing for this new action.
- Updated SendSESNotificationAction as there was some new details that needed to be passed to templates from S3.
  - Updated SendSESNotificationAction's unit tests.
  - Updated SendSESNotificationAction's integration tests.
- Updated SendSNSNotificationAction as there was issues with the enriched data being represented as string instead of pure JSON. To fix it, we instead pass the JSON serialized object directly to SNS, instead of tinkering around with templates.
  - Removed sns/*.json.j2 files
- Completed S3CompromisedDiscoveryPlaybook
  - Created E2E tests for this playbook
- Modified templates to be pure HTML, renamed all template files to be *.html.j2
- Removed Markdown as a dependency and recompiled the requirements.txt files
- Fixed some Mypy errors.

## [0.4.0] - 2025-10-16

### Added
- Added Bandit and Safety packages to dev dependencies. We will use these
for dependency scanning and static code analysis. 
- Updated pull request documentation to reflect the needed two more steps.
- Updated GetCloudTrailHistoryAction to be more universal, allowing it to be reused in S3 playbooks. It now takes a KWARG for lookup_attributes, which filters the CloudTrail responses to specific items. Validated unit, integration and e2e tests all still pass.
- Added new action: S3BlockPublicAccessAction.
  - Added unit testing for this new action.
  - Added integration tests for this new action.

## [0.3.0] - 2025-10-16

### Added
- Creation of S3 data models and templates for notifications.
- Creation of EnrichS3Action.
  - Creation of unit tests for EnrichS3Action.
  - Creation of integration tests for EnrichS3Action.
- Added MkDocs to development packages.
  - Added documents from other repo to this repo, to make self-containing.
- Modified TagS3BucketAction to handle the updated data models and templates.


## [0.2.0] - 2025-10-16

### Added
- Creation of TagS3BucketAction
  - Creation of unit tests for TagS3BucketAction (single and multiple buckets).
  - Creation of integration tests for TagS3BucketAction (single and multiple buckets).

## [0.1.0] - 2025-10-16

### Added
- **Core Engine**: Initial implementation of the SOAR engine to process GuardDuty findings.
- **Configuration**: Robust, layered configuration system using `gd.cfg` and environment variables.
- **EC2 Playbooks**:
  - `EC2InstanceCompromisePlaybook` for comprehensive remediation.
  - `EC2BruteForcePlaybook` for blocking malicious IPs.
  - `EC2UnprotectedPortPlaybook` for closing public ports.
- **IAM Playbook**:
  - `IamForensicsPlaybook` for gathering evidence on User, Role, and Root findings.
- **Actions**: A modular library of actions for EC2 and IAM (e.g., `IsolateInstanceAction`, `AnalyzePermissionsAction`).
- **Testing**: Comprehensive unit, integration, and E2E test suites using `pytest`.
- **Documentation**: Initial project documentation in GitBook.