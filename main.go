package main

import (
	"flag"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/hashicorp/vault/api"
	"github.com/oulman/check-cloudwatch/response"
)

var client *api.Client

type AWSCreds struct {
	access_key     string
	secret_key     string
	security_token string
}

// vaultAppRoleLogin() authenticates to vault using the AppRole method and
// returns a token
func vaultApproleLogin() (string, error) {
	conf := api.DefaultConfig()

	var err error

	client, err = api.NewClient(conf)
	if err != nil {
		log.Fatal(err)
		return "", err
	}

	myRoleID := os.Getenv("VAULT_ROLE_ID")
	mySecretID := os.Getenv("VAULT_SECRET_ID")

	resp, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   myRoleID,
		"secret_id": mySecretID,
	})
	if err != nil {
		log.Fatal(err)
	}
	return resp.Auth.ClientToken, nil
}

// getAwsToken()
func getAwsToken(roleArn string) (*AWSCreds, error) {

	var creds AWSCreds

	conf := api.DefaultConfig()

	var err error

	client, err = api.NewClient(conf)
	if err != nil {
		log.Fatal(err)
		return &creds, err
	}

	token, err := vaultApproleLogin()
	if err != nil {
		log.Fatal(err)
		return &creds, err
	}

	client.SetToken(token)

	resp, err := client.Logical().Write("/aws/sts/nagios", map[string]interface{}{
		"role_arn": roleArn,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Verify that Vault AWS secrets engine response returns a string that can be
	// passed into AWSCreds
	access_key, ok := resp.Data["access_key"].(string)
	if !ok {
		log.Fatal("Vault response access_key is not a string")
		return &creds, err
	}

	secret_key, ok := resp.Data["secret_key"].(string)
	if !ok {
		log.Fatal("Vault response secret_key is not a string")
		return &creds, err
	}

	security_token, ok := resp.Data["security_token"].(string)
	if !ok {
		return &creds, err
	}

	creds.access_key = access_key
	creds.secret_key = secret_key
	creds.security_token = security_token

	return &creds, err

}

func main() {
	// Policy required to read alarm information: cloudwatch:DescribeAlarms
	// Credentials file must contain access_key and secret_key (see: https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html#specifying-credentials)
	// Profile specifies which profile within the credentials file to use
	roleArn := flag.String("rolearn", "", "role_arn to pass to the Vault AWS STS secrets engine endpoint")
	region := flag.String("region", "", "Region to perform the check in")
	alarm := flag.String("alarm", "", "Name of the CloudWatch alarm to check")
	alarmType := flag.String("alarmtype", "metricalarm", "Cloudwatch alarm type: metricalarm or compositealarm")

	flag.Parse()

	if *roleArn == "" || *region == "" || *alarm == "" {
		response.Unknown("Required options not specified: [rolearn region alarm]").Exit()
	}

	// authenticate to vault using appRole auth method and get a token
	//token, err := vaultApproleLogin()
	//if err != nil {
	//	log.Fatal("Unable to login to Vault")
	//}

	creds, err := getAwsToken(*roleArn)
	if err != nil {
		response.Critical("Unable to get AWS credentials from secrets engine").Exit()
	}

	// DescribeAlarmsInput struct provides filtering of CloudWatch alarms by name
	// Alarm names are specified as a slice of string pointers (Nagios will only ever pass a single alarm name)
	var input cloudwatch.DescribeAlarmsInput
	var alarmNames []*string
	alarmNames = append(alarmNames, alarm)
	input.AlarmNames = alarmNames

	var alarmTypes []string = []string{"CompositeAlarm", "MetricAlarm"}
	input.AlarmTypes = aws.StringSlice(alarmTypes)

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(*region),
		Credentials: credentials.NewStaticCredentials(creds.access_key, creds.secret_key, creds.security_token),
	})
	svc := cloudwatch.New(sess)

	resp, err := svc.DescribeAlarms(&input)
	if err != nil {
		response.Unknown("error retrieving alarm data: " + err.Error()).Exit()
	}

	var output string
	var state string

	switch *alarmType {
	case "metricalarm":
		if len(resp.MetricAlarms) < 1 {
			response.Unknown("alarm not found - check region and alarm name").Exit()
		}
		for _, alarm := range resp.MetricAlarms {
			output = *alarm.StateReason
			state = *alarm.StateValue
		}
	case "compositealarm":
		if len(resp.CompositeAlarms) < 1 {
			response.Unknown("alarm not found - check region and alarm name").Exit()
		}
		for _, alarm := range resp.CompositeAlarms {
			output = *alarm.StateReason
			state = *alarm.StateValue
		}
	default:
		response.Unknown("Invalid --alarmtype specified!").Exit()
	}

	switch state {
	case "OK":
		response.Ok(output).Exit()
	case "ALARM":
		response.Critical(output).Exit()
	default:
		response.Unknown(output).Exit()
	}

}
