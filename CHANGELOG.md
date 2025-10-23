# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNRELEASED]

### Added


## [0.14.0] - 2025-10-22

### Added
- Added new configuration "allow_gather_recent_queries" that when enabled allows the playbook to capture recent queries ran by a user from a GuardDuty RDS finding. This action is optional but also requires the RDS instance be setup with logging enabled for that engine.
- Added new action GatherRecentQueriesAction
  - Added unit tests and integration tests.

## [0.13.0] - 2025-10-22

### Added
- Added new IdentifyRdsUserAction
  - Added unit tests and integration tests.
- Added updated Rds user schema model
- Updated .env.example file with all current configurations

## [0.12.0] - 2025-10-20

### Added
- Added new ModifyRdsPublicAccessAction, which attempts to remove public access from an RDS instance
  - Added unit tests and integration tests.
- Added configuration, as this new action is optional and can be turned off/on.

## [0.11.0] - 2025-10-20

### Added
- Added new EnrichRdsFindingAction, which attempts to grab as much details as possible for the instance.
  - Added unit tests for this new action
  - Added to the integration tests for RDS actions.
- Added RdsEnrichmentData Pydantic model to enforce schema.

## [0.10.0] - 2025-10-19

### Added
- Added new RDS action: TagRdsInstanceAction, which can tag one or more RDS instances from findings with GuardDuty-SOAR finding tags.
  - Added unit tests and integration tests.

## [0.9.0] - 2025-10-19

### Added
- Added `playbooks` directory with subdirectories
  - Added `actions` directory for custom end-user actions
  - Added `playbooks` directory for custom end-user playbooks
- Updated `main.py` to handle the additional lookup of plugins directory.
- Updated `test_main.py` unit tests to thoroughly test this new functionality.
- Update documentation for this new functionality.
- Created unit tests and a validation scenario for this new functionality.

## [0.8.0] - 2025-10-18

### Added
- Added RDS finding types for schema.py, models.py and created communication templates for its data.

## [0.7.3] - 2025-10-18

### Added
- Updated documentation:
  - Includes S3 playbooks and actions now.
  - Updated consistent theming across.

## [0.7.2] - 2025-10-18

### Added
- Added validation scenarios:
  - Two for S3BucketExposurePlaybook, one with a single bucket and one with more than one bucket.
  - Two for S3CompromisedDiscoveryPlaybook, one with a single bucket and one with more than one bucket.
- DataLossPrevention's E2E test is better suited for testing then a validation scenario, so we did not create one for that playbook specifically.
- Updated import statements in multiple locations due to type checking. Made the special types conditional imports as well as those files now also import annotations from __future__.

## [0.7.1] - 2025-10-18

### Added
- There is a condition that an S3 bucket could be a "Directory bucket". If a S3 bucket found is a directory bucket, 99% of the APIs we use will not work on them. But since there is a scenario where GuardDuty could pass none, 1 or more buckets being directory buckets, we have to inspect each at the beginning of every action. This has been implemented.
  - Unit tests for all actions have been updated with this new conditional logic 

## [0.7.0] - 2025-10-18

### Added
- Added playbook S3BucketExposurePlaybook, performs all the functionality of S3CompromisedDiscoveryPlaybook, but also runs the optional step of attaching an S3 block public access policy.
  - Created E2E tests for this new playbook.

## [0.6.0] - 2025-10-17

### Added
- Added S3DataLossPreventionPlaybook, performs all the functionality of S3CompromisedDiscoveryPlaybook, but also parses recent history in CloudTrail (based on the configuration `cloudtrail_history_max_results`).
  - Designed E2E tests for this new playbook.
- Updated GetCloudTrailHistoryAction to be parse the CloudTrail event JSON. This produces a more readable end-JSON object for SNS.
- Updated S3 Jinja template to include CloudTrail findings, previously was not included.
- Added Apache 2.0 license: LICENSE

## [0.5.1] - 2025-10-17

### Added
- Refactored EC2InstanceCompromisePlaybook to no longer inherit the instance compromise workflow from the base EC2 playbook class. This allows the base EC2 playbook class to model all other base playbook classes. With this refactor, we now have EC2BruteForcePlaybook inherit from EC2InstanceCompromisePlaybook (instead of EC2BasePlaybook), so if the conditional logic points towards the instance being compromised, we can run the EC2InstanceCompromisePlaybook through `super()`. 

## [0.5.0] - 2025-10-17

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