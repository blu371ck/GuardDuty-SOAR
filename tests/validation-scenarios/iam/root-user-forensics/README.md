# IAM Forensics Playbook Root User

### Objective: 
This scenario validates that the IamForensicsPlaybook correctly identifies the Root user and skips the tagging action (as you cannot tag the Root principal).

**No Terraform is required for this test.**

### Instructions
1. Prepare the Test Event:
    - Open the event.json file.
    - Replace the placeholder YOUR_AWS_ACCOUNT_ID with your actual 12-digit AWS Account ID.

2. Invoke the Lambda Function:
```bash
aws lambda invoke --function-name Your-GuardDuty-SOAR-FunctionName --payload file://event.json response.json
```
**NOTE:** You can also use the Lambda console to test by pasting the contents of the `event.auto.json` into a new Lambda test and then invoke that test.

3. Verify the Results:
- Check your notifications. The actions_summary should show that the TagPrincipal action has a status of SKIPPED. All other actions should be successful.

### Cleanup
No cleanup required.