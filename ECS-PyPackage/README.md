# Unused-AWS Resources in AWS ECS with python 3.6

This python deployment package allows you to identify un-used aws resources in AWS ECS Task-cloudwatch event rule with python 3.6 runtime.

Clone the repo and then simply add your related details in  `MakeFile` and then run the follwoing commands:

Note: Need VPC and subnet for running the ECS Task. 

To create Cluster and ECR 

```Make create_cluster_ecr```

To get ECR Image URI 

```Make getecruri```

To push the image , need to login to ECR 

```Make ecrlogin```

To build and push the code to ECR 

```Make build```

To create Task Definition and Cloudwatch Event 

```Make create_stack```

For sending mail , i have configured the mail id in AWS SES. If you have any other option , you can make use of that also. 

Enjoy!