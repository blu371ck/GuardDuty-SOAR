# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Creation of TagS3BucketAction

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