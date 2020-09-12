# Unused-AWS Resources in AWS Lambda with python 3.6

This python deployment package allows you to identify un-used aws resources in AWS Lambda-cloudwatch event rule with python 3.6 runtime.

Clone the repo and then simply add your related details in  `MakeFile` and then run the follwoing commands:

```Make package```

```Make create_stack```

If you dont have s3 buckets , then first execute the below command 

```Make create_bucket```

For sending mail , i have configured the mail id in AWS SES. If you have any other option , you can make use of that also. 

Enjoy!