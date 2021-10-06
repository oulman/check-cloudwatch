# check-cloudwatch

check-cloudwatch is a simple CLI program, utilising the AWS SDK, to check the status of a specified CloudWatch alarm.  
The program is designed to be used by Nagios and so will exit with the following exit codes, and echo a description of the alert.

- RC 0: OK
- RC 2: CRITICAL
- RC 3: UNKNOWN

It was forked from [jakgibb/cherck-cloudwatch](https://github.com/jakgibb/check-cloudwatch) and updated to use the HashiCorp Vault
AppRole login and the AWS Secrets Engine.

### Setup

The `cloudwatch:DescribeAlarms` policy is required to read CloudWatch alarms

Set up your Vault environment variables

```
export VAULT_ADDR="https://active.vault.service.my.consul:8200"
export VAULT_ROLE_ID="xxxx"
export VAULT_SECRET_ID="xxxx"
```

### Usage

Create a Nagios command to run the script (`go run`) or invoke the executable (if built with `go build`)  
`/usr/local/nagios/libexec/check_cloudwatch --rolearn $ARG1$ --region $ARG2$ --alarm $ARG3$ --alarmtype $ARG4$ `

Where --alarmtype is one of:

- metricalarm
- compositealarm

### Example

```
/usr/local/nagios/libexec/check-cloudwatch --rolearn arn:aws:iam::111111111111:role/Nagios --region us-east-1 --alarm asg-running-vs-desired-alarm --alarmtype metricalarm
 OK: Threshold Crossed: 1 out of the last 3 datapoints [0.0 (04/10/21 21:42:00)] was not greater than the threshold (0.1) (minimum 1 datapoint for ALARM -> OK transition).
/usr/local/nagios/libexec/check-cloudwatch --rolearn arn:aws:iam::111111111111:role/Nagios --region us-east-1 --alarm asg-disk-composite --alarmtype compositealarm
 OK: arn:aws:cloudwatch:us-east-1:111111111111:alarm:asg-disk-composite was updated and its new alarm rule evaluates to OK
```
