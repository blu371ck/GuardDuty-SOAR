# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [UNRELEASED]

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