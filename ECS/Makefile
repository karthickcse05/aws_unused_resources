PROFILE = idsbx
ENVIRONMENT = sbx
PREFIX = int-docs
Sender = karthickcse05@gmail.com
Receiver = karthick.s@emishealth.com
Days = 14
application = int-docs
ECRImageURI = 570050899301.dkr.ecr.eu-west-2.amazonaws.com/sbx-unused-ecr
ECRRepoName = sbx-unused-ecr
VPCID = vpc-040dcb6c436e97550



.PHONY: explain
explain:
		#                                                                                                                                                        
		# 
  #     ___ _       _______    __  __                          __   ____                                           
  #    /   | |     / / ___/   / / / /___  __  __________  ____/ /  / __ \___  _________  __  _______________  _____
  #   / /| | | /| / /\__ \   / / / / __ \/ / / / ___/ _ \/ __  /  / /_/ / _ \/ ___/ __ \/ / / / ___/ ___/ _ \/ ___/
  #  / ___ | |/ |/ /___/ /  / /_/ / / / / /_/ (__  )  __/ /_/ /  / _, _/  __(__  ) /_/ / /_/ / /  / /__/  __(__  ) 
  # /_/  |_|__/|__//____/   \____/_/ /_/\__,_/____/\___/\__,_/  /_/ |_|\___/____/\____/\__,_/_/   \___/\___/____/  
                                                                                                               

		#
		### Targets
		#
		@cat Makefile* | grep -E '^[a-zA-Z_-]+:.*?## .*$$' | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'



.PHONY: getecruri
getecruri: ## gets the ecr repo uri
	#aws ecr describe-repositories --repository-names ${ECRRepoName}  | grep \"repositoryUri\" | cut -f4 -d\" --profile $(PROFILE)
	aws ecr describe-repositories --repository-names ${Environment}-unused-ecr  --profile $(PROFILE)

.PHONY: ecrlogin
ecrlogin: ## login to the ECR
	aws ecr get-login --region eu-west-2 --no-include-email --profile $(PROFILE)
	# take the docker login and enter in command prompt

.PHONY: build
build: ## Zips the code to the docker image and push it
	cd src
	docker build -t awsunused:latest .
	docker tag awsunused:latest $(ECRImageURI):latest
	docker push $(ECRImageURI):latest
	

.PHONY: create_stack
create_stack: ## Creates a  cloudformation stack in AWS
		make deploy ACTION=create

.PHONY: update_stack
update_stack: ## Updates an existing cloudformation stack in AWS
		make deploy ACTION=update


.PHONY: deploy
deploy:  ## deploy the  cloudformation stack in AWS
	aws cloudformation $(ACTION)-stack \
	--stack-name ${PREFIX}-$(ENVIRONMENT)-awsunusedresources \
	--template-body file://infrastructure/aws-unused-resources.yaml \
	--profile $(PROFILE) \
	--capabilities  CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
	--parameters \
		ParameterKey=sender,ParameterValue=$(Sender) \
		ParameterKey=receiver,ParameterValue=$(Receiver) \
		ParameterKey=env,ParameterValue=$(ENVIRONMENT) \
		ParameterKey=days,ParameterValue=$(Days) \
		ParameterKey=application,ParameterValue=$(application) \
		ParameterKey=VpcId,ParameterValue=$(VPCID) \
		ParameterKey=AWSUnusedImage,ParameterValue=$(ECRImageURI) \
		ParameterKey=Prefix,ParameterValue=$(PREFIX) \

.PHONY: create_cluster_ecr
create_cluster_ecr: ## Creates a new ecr cloudformation stack in AWS
		make create_update_ecr ACTION=create

.PHONY: update_cluster_ecr
update_cluster_ecr: ## Updates an existing ecr cloudformation stack in AWS
		make create_update_ecr ACTION=update

.PHONY: create_update_ecr
create_update_ecr: ## Creates or updates the ecr cloudformation stack based on the action
	aws cloudformation $(ACTION)-stack \
	--stack-name ${PREFIX}-$(ENVIRONMENT)-ecr \
	--template-body file://infrastructure/pre-requistes/ecr-stack.yaml \
	--profile $(PROFILE) \
	--capabilities CAPABILITY_NAMED_IAM \
	--parameters \
		ParameterKey=Environment,ParameterValue=$(ENVIRONMENT) \
