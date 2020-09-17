PROFILE = 
ENVIRONMENT = sbx
PREFIX = 
Sender = 
Receiver = 
Days = 14
BucketName = 
application = 



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


.PHONY: build
build: ## alternative build # to run this you need WSL in your system
	cd src
	apt update
	apt-get install -y libsasl2-dev python3-dev libldap2-dev libssl-dev python3-pip
	pip3 install -r requirements.txt --target .
	zip -qr lambdas.zip ./*


.PHONY: package
package: ## packages the file in s3
	aws cloudformation package \
    --template-file "infrastructure\aws-unused-resources.yaml" \
    --s3-bucket  $(BucketName) \
    --output-template-file "aws-unused-resources-release.yaml" \
	--profile  $(PROFILE) \


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
	--template-body file://aws-unused-resources-release.yaml \
	--profile $(PROFILE) \
	--capabilities  CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
	--parameters \
		ParameterKey=sender,ParameterValue=$(Sender) \
		ParameterKey=receiver,ParameterValue=$(Receiver) \
		ParameterKey=env,ParameterValue=$(ENVIRONMENT) \
		ParameterKey=days,ParameterValue=$(Days) \
		ParameterKey=application,ParameterValue=$(application) \

.PHONY: create_bucket
create_bucket: ## Creates a new bucket cloudformation stack in AWS
		make create_update_bucket ACTION=create

.PHONY: update_bucket
update_bucket: ## Updates an existing bucket cloudformation stack in AWS
		make create_update_bucket ACTION=update

.PHONY: create_update_bucket
create_update_bucket: ## Creates or updates the bucket cloudformation stack based on the action
	aws cloudformation $(ACTION)-stack \
	--stack-name ${PREFIX}-$(ENVIRONMENT)-buckets \
	--template-body file://infrastructure/pre-requistes/artifact-store-stack.yaml \
	--profile $(PROFILE) \
	--capabilities CAPABILITY_NAMED_IAM \
	--parameters \
		ParameterKey=StackPrefix,ParameterValue=$(PREFIX) \
		ParameterKey=Environment,ParameterValue=$(ENVIRONMENT) \
