import json
import boto3
import os
#from datetime import date, timedelta
import datetime
from _datetime import timedelta
import pandas as pd
from botocore.exceptions import ClientError
import re
import numpy as np


def data_table(df,column):
    result_table = '<table border = 1><tr bgcolor="Blue"><th>Resource Type</th><th>Resource Name / Id</th><th>{}</th></tr>'
    result_table = result_table.format(column)
    #print(column)
    #print(result_table)
    for index, row in df.iterrows():
        result_table += '<tr><td>{}</td><td>{}</td><td>{}</td>'.format(
            row['resourceType'], row['resourceName'], row['reason'])
    result_table += '</table>'
    return result_table


def getAvailableVolumes():
    # returns list of volumes in 'available' state
    ec2 = boto3.client('ec2')
    availableVolList = []
    filterList = [{'Name': 'status', 'Values': ['available']}]
    response = ec2.describe_volumes(Filters=filterList, MaxResults=500)
    if(len(response['Volumes'])> 0):
        for v in response['Volumes']:
            if(len(v['Attachments'])) == 0:
                availableVolList.append(v['VolumeId'])
        while('NextToken' in response):
            response = ec2.describe_volumes(
                Filters=filterList, MaxResults=500, NextToken=response['NextToken'])
            for v in response['Volumes']:
                if(len(v['Attachments'])) == 0:
                    availableVolList.append(v['VolumeId'])
    return availableVolList

def getLogsWithNoRetention():
    # returns list of log groups with no retention days
    cw = boto3.client('logs')
    loggroups = ['/aws','API-Gateway','RDSOSMetrics','test',os.environ['env'],'/ecs']
    logswithNoRetention = []
    for groupname in loggroups:
        cwresponse = cw.describe_log_groups(logGroupNamePrefix=groupname)
        if(len(cwresponse['logGroups']) > 0):
            for v in cwresponse['logGroups']:
                if "retentionInDays" not in v:
                    logswithNoRetention.append(v['logGroupName'])
    return logswithNoRetention

def getNotAssociatedEIP():
    # returns list of EIP in 'not used' state
    ec2 = boto3.client('ec2')
    availableEIPList = []
    eipresponse = ec2.describe_addresses()
    if(len(eipresponse['Addresses']) > 0):
        for address in eipresponse['Addresses']:
            if "AssociationId" not in address:
                availableEIPList.append(address['AllocationId'])
    return availableEIPList

def getUnusedRDSSnapshot(startdate):
    # returns list of snapshots in 'not used' state
    rds = boto3.client('rds')
    unUsedRDSsnapshotlList = []
    rdsresponse = rds.describe_db_cluster_snapshots()
    if(len(rdsresponse['DBClusterSnapshots']) > 0):
        for snapshot in rdsresponse['DBClusterSnapshots']:
            if(snapshot['SnapshotCreateTime'].replace(tzinfo=None) < startdate):
                unUsedRDSsnapshotlList.append(snapshot['DBClusterSnapshotIdentifier'])
        while('Marker' in rdsresponse):
            rdsresponse = rds.describe_db_cluster_snapshots(Marker = rdsresponse['Marker'])
            if(snapshot['SnapshotCreateTime'].replace(tzinfo=None) < startdate):
                unUsedRDSsnapshotlList.append(snapshot['DBClusterSnapshotIdentifier'])       
    return unUsedRDSsnapshotlList 

def getUnusedEBSSnapshot(startdate):
    # returns list of snapshots in 'not used' state
    ebs = boto3.client('ec2')
    unUsedEBSsnapshotlList = []
    ebsresponse = ebs.describe_snapshots()
    if(len(ebsresponse['Snapshots']) > 0):
        for snapshot in ebsresponse['Snapshots']:
            if(snapshot['StartTime'].replace(tzinfo=None) < startdate):
                unUsedEBSsnapshotlList.append(snapshot['VolumeId'])
        while('NextToken' in ebsresponse):
            ebsresponse = ebs.describe_db_cluster_snapshots(NextToken = ebsresponse['NextToken'])
            if(snapshot['StartTime'].replace(tzinfo=None) < startdate):
                unUsedEBSsnapshotlList.append(snapshot['VolumeId'])       
    return unUsedEBSsnapshotlList

def getUnusedES():
    # returns list of EIP in 'not used' state
    es = boto3.client('es')
    escw = boto3.client('cloudwatch')
    availableDomainNameList = []
    unUsedDomainNameList = []
    esresponse = es.list_domain_names()
    if(len(esresponse['DomainNames']) > 0):
        for data in esresponse['DomainNames']:
            if "DomainName" in data:
                availableDomainNameList.append(data['DomainName'])

    if(len(availableDomainNameList) > 0 ):
        for domainname in availableDomainNameList:
            MetricName = ["CPUUtilization"]
            for metric in MetricName:
                instancemetricresponse = escw.get_metric_statistics(
                    Namespace="AWS/ES",
                    MetricName=metric,
                    Dimensions=[
                        {'Name': 'DomainName',
                            'Value': domainname}
                    ],
                    StartTime=datetime.datetime.utcnow() - timedelta(days=7),
                    EndTime=datetime.datetime.utcnow(),
                    Statistics=["Average"],
                    Period=3600  #604800
                )
                # print(instancemetricresponse)
                # metricdata.append(instancemetricresponse)
                average = 0
                #print(len(instancemetricresponse['Datapoints']))
                for r in instancemetricresponse['Datapoints']:
                    average = average + r['Average']
                #print("average: " ,average)    
                # print(average)    
                if (round(average,2)) < 60:
                    unUsedDomainNameList.append(domainname)          
    return unUsedDomainNameList 

def getUnusedECS():
    # returns list of EIP in 'not used' state
    ecs = boto3.client('ecs')
    ecscw = boto3.client('cloudwatch')
    availableserviceList = []
    unUsedECSServiceList = []
    ecsresponse = ecs.list_clusters()
    if(len(ecsresponse['clusterArns']) > 0):
        for cluster in ecsresponse['clusterArns']:
            ecsserviceresponse = ecs.list_services(cluster=cluster.split(":")[5].split("/",1)[1])
            if (len(ecsserviceresponse['serviceArns'])) > 0:
                for service in ecsserviceresponse['serviceArns']:
                    availableserviceList.append(service.split(":")[5].split("/",1)[1])

    if(len(availableserviceList) > 0 ):
        for servicename in availableserviceList:
            MetricName = ["CPUUtilization"]
            for metric in MetricName:
                instancemetricresponse = ecscw.get_metric_statistics(
                    Namespace="AWS/ECS",
                    MetricName=metric,
                    Dimensions=[
                        {'Name': 'ServiceName',
                            'Value': servicename}
                    ],
                    StartTime=datetime.datetime.utcnow() - timedelta(days=7),
                    EndTime=datetime.datetime.utcnow(),
                    Statistics=["Average"],
                    Period=3600  #604800
                )
                # print(instancemetricresponse)
                # metricdata.append(instancemetricresponse)
                average = 0
                #print(len(instancemetricresponse['Datapoints']))
                for r in instancemetricresponse['Datapoints']:
                    average = average + r['Average']
                #print("average: " ,average)    
                # print(average)    
                if (round(average,2)) < 60:
                    unUsedECSServiceList.append(servicename)          
    return unUsedECSServiceList              


def getNotUsedSG():
    # returns list of SG in 'not used' state
    ec2 = boto3.client('ec2')
    elbclient = boto3.client('elbv2')
    rdsclient = boto3.client('rds')
    allgroups = []
    groups = ec2.describe_security_groups()
    for groupobj in groups['SecurityGroups']:
        allgroups.append(groupobj['GroupName'])

    # Get all instances security groups (EC2)
    groups_in_use = []
    reservations = ec2.describe_instances()
    for r in reservations['Reservations']:
        for ec2_group_list in r['Groups']:
            # print(ec2_group_list)
            for groupname in ec2_group_list:
                if groupname['GroupName'] not in groups_in_use:
                    groups_in_use.append(groupname)

    # Get all security groups from ELB
    load_balancers = elbclient.describe_load_balancers()
    for load_balancer in load_balancers:
        if 'SecurityGroups' in load_balancer:
            for elb_group_list in load_balancer['SecurityGroups']:
                # print(elb_group_list)
                security_group = ec2.describe_security_groups(
                    GroupIds=[elb_group_list])
                for groupobj in security_group['SecurityGroups']:
                    if groupobj['GroupName'] not in groups_in_use:
                        groups_in_use.append(groupobj['GroupName'])

    # Get all security groups from Networ Interfaces
    niresponse = ec2.describe_network_interfaces()
    for network_interface in niresponse['NetworkInterfaces']:
        # print(network_interface)
        if 'Groups' in network_interface:
            for ni_group_list in network_interface['Groups']:
                # print(ni_group_list['GroupName'])
                if ni_group_list['GroupName'] not in groups_in_use:
                    groups_in_use.append(ni_group_list['GroupName'])

    # Get all security groups from RDS
    dbresponse = rdsclient.describe_db_instances()
    for db in dbresponse['DBInstances']:
        if 'VpcSecurityGroups' in db:
            for db_group_list in db['VpcSecurityGroups']:
                # print(db_group_list)
                db_security_group = ec2.describe_security_groups(
                    GroupIds=[db_group_list['VpcSecurityGroupId']])
                # print(db_security_group)
                for groupobj in db_security_group['SecurityGroups']:
                    # print(groupobj['GroupName'])
                    if groupobj['GroupName'] not in groups_in_use:
                        groups_in_use.append(groupobj['GroupName'])

    unnused_SG = []
    for group in allgroups:
        if group not in groups_in_use:
            unnused_SG.append(group)
    return unnused_SG


def lambda_handler(event, context):
    print('Enumerating all resources in the following services:')
    startTime = datetime.datetime.utcnow(
    ) - timedelta(days=int(os.environ['days']))
    endTime = datetime.datetime.utcnow()
    seconds_in_one_day = 1209600  # 86400  # used for granularity

    configclient = boto3.client('config')
    resources = ['AWS::EC2::EIP', 'AWS::EC2::Host', 'AWS::EC2::Instance',
                 'AWS::EC2::Volume',
                 'AWS::EC2::VPC',
                 'AWS::EC2::NatGateway', 'AWS::ElasticLoadBalancingV2::LoadBalancer', 'AWS::ACM::Certificate',
                 'AWS::RDS::DBInstance', 'AWS::RDS::DBSnapshot',
                 'AWS::RDS::DBCluster', 'AWS::RDS::DBClusterSnapshot', 'AWS::S3::Bucket',
                 'AWS::CloudWatch::Alarm',
                 'AWS::CloudFormation::Stack', 'AWS::ElasticLoadBalancing::LoadBalancer', 'AWS::AutoScaling::AutoScalingGroup',
                 'AWS::AutoScaling::LaunchConfiguration', 'AWS::AutoScaling::ScalingPolicy',
                 'AWS::DynamoDB::Table', 'AWS::CodeBuild::Project', 'AWS::WAF::RateBasedRule', 'AWS::WAF::Rule', 'AWS::WAF::RuleGroup',
                 'AWS::WAF::WebACL', 'AWS::WAFRegional::RateBasedRule', 'AWS::WAFRegional::Rule', 'AWS::WAFRegional::RuleGroup',
                 'AWS::WAFRegional::WebACL', 'AWS::CloudFront::Distribution', 'AWS::CloudFront::StreamingDistribution',
                 'AWS::Lambda::Function', 'AWS::ApiGateway::Stage',
                 'AWS::ApiGateway::RestApi', 'AWS::ApiGatewayV2::Stage', 'AWS::ApiGatewayV2::Api',
                 'AWS::CodePipeline::Pipeline',
                 'AWS::SQS::Queue', 'AWS::KMS::Key', 'AWS::SecretsManager::Secret',
                 'AWS::SNS::Topic', ]
    datas = []
    for resource in resources:
        response = configclient.list_discovered_resources(
            resourceType=resource
        )
        datas.append(response['resourceIdentifiers'])

    cloudwatchclient = boto3.client('cloudwatch')

    resourceType = []
    resourceName = []
    reason = []
    count = []

    cwresourceType = []
    cwresourceName = []
    cwreason = []

    lmdresourceType = []
    lmdresourceName = []
    lmdpackagesize=[]

    s3resourceType = []
    s3resourceName = []
    s3size=[]

    # EBS
    ebsVolumes = getAvailableVolumes()
    # print(ebsVolumes)
    if(len(ebsVolumes) > 0):
        for volumes in ebsVolumes:
            # print(volumes)
            resourceType.append("AWS::EC2::Volume")
            resourceName.append(volumes)
            reason.append("EC2 Volume is Not Used")
            count.append(1)

    # EIP
    eipData = getNotAssociatedEIP()
    # print(eipData)
    if(len(eipData) > 0):
        for address in eipData:
            # print(volumes)
            resourceType.append("AWS::EC2::EIP")
            resourceName.append(address)
            reason.append("EIP is Not Used")
            count.append(1)

    # RDS Snapshots
    rdsData = getUnusedRDSSnapshot(startTime)
    # print(eipData)
    if(len(rdsData) > 0):
        for data in rdsData:
            # print(volumes)
            resourceType.append("AWS::RDS::SNAPSHOT")
            resourceName.append(data)
            reason.append("Long Back created RDS Cluster SnapShot is still available")
            count.append(1) 

    # Elastic Search
    esData = getUnusedES()
    # print(eipData)
    if(len(esData) > 0):
        for data in esData:
            # print(volumes)
            resourceType.append("AWS::Elasticsearch::Domain")
            resourceName.append(data)
            reason.append("Elastic Search domain is underutilized")
            count.append(1) 

    # Elastic Container Service
    ecsData = getUnusedECS()
    # print(eipData)
    if(len(ecsData) > 0):
        for data in ecsData:
            # print(volumes)
            resourceType.append("AWS::ECS::Service")
            resourceName.append(data)
            reason.append("Elastic Container Service is underutilized")
            count.append(1)                 

    # SG
    sgData = getNotUsedSG()
    # print(sgData)
    if(len(sgData) > 0):
        for sggroup in sgData:
            # print(sggroup)
            resourceType.append("AWS::EC2::SecurityGroup")
            resourceName.append(sggroup)
            reason.append("Security Group is Not Used")
            count.append(1)

    # CloudWatch Log Groups
    cwData = getLogsWithNoRetention()
    # print(sgData)
    if(len(cwData) > 0):
        for cwgroup in cwData:
            # print(sggroup)
            cwresourceType.append("AWS::Logs::LogGroup")
            cwresourceName.append(cwgroup)
            cwreason.append("Retention Days is not specified")

    for data in datas:
        for getvalue in data:
            if getvalue["resourceType"] == "AWS::DynamoDB::Table":
                # print(getvalue["resourceId"])
                MetricName = ["ConsumedReadCapacityUnits",
                              "ConsumedWriteCapacityUnits"]
                for metric in MetricName:
                    metricresponse = cloudwatchclient.get_metric_statistics(
                        Namespace="AWS/DynamoDB",
                        MetricName=metric,
                        Dimensions=[
                            {'Name': 'TableName',
                                'Value': getvalue["resourceId"]}
                        ],
                        StartTime=startTime,
                        EndTime=endTime,
                        Statistics=["Sum"],
                        Period=seconds_in_one_day
                    )
                    # print(metricresponse)
                    # metricdata.append(metricresponse)
                    for r in metricresponse['Datapoints']:
                        if (r['Sum']) == 0:
                            #print("Not  usable")
                            resourceType.append(getvalue["resourceType"])
                            resourceName.append(getvalue["resourceId"])
                            count.append(1)
                            if metric == "ConsumedReadCapacityUnits":
                                reason.append("Read capacity is not used")
                            else:
                                reason.append("Write capacity is not used")

            if getvalue["resourceType"] == "AWS::ElasticLoadBalancingV2::LoadBalancer" and getvalue["resourceId"].split(":")[5].split("/", 1)[1].split("/")[0] == "net":
                # print(getvalue["resourceId"])
                # ActiveFlowCount
                MetricName = ["NewFlowCount", "ActiveFlowCount"]
                for metric in MetricName:
                    lbmetricresponse = cloudwatchclient.get_metric_statistics(
                        Namespace="AWS/NetworkELB",
                        MetricName=metric,
                        Dimensions=[
                            {'Name': 'LoadBalancer',
                                'Value': getvalue["resourceId"].split(":")[5].split("/", 1)[1]}
                        ],
                        StartTime=startTime,
                        EndTime=endTime,
                        Statistics=["Sum"],
                        Period=seconds_in_one_day
                    )
                    # print(lbmetricresponse)
                    for r in lbmetricresponse['Datapoints']:
                        if (r['Sum']) == 0:
                            #print("Not  usable")
                            resourceType.append(getvalue["resourceType"])
                            resourceName.append(getvalue["resourceId"].split(
                                ":")[5].split("/", 1)[1].split("/")[1])
                            reason.append("Network LoadBalancer is not used")
                            count.append(1)

            if getvalue["resourceType"] == "AWS::ElasticLoadBalancingV2::LoadBalancer" and getvalue["resourceId"].split(":")[5].split("/", 1)[1].split("/")[0] == "app":
                # print(getvalue["resourceId"])
                MetricName = ["RequestCount", "ConsumedLCUs"]
                for metric in MetricName:
                    albmetricresponse = cloudwatchclient.get_metric_statistics(
                        Namespace="AWS/ApplicationELB",
                        MetricName=metric,
                        Dimensions=[
                            {'Name': 'LoadBalancer',
                                'Value': getvalue["resourceId"].split(":")[5].split("/", 1)[1]}
                        ],
                        StartTime=startTime,
                        EndTime=endTime,
                        Statistics=["Sum"],
                        Period=seconds_in_one_day
                    )
                    # print(albmetricresponse)
                    for r in albmetricresponse['Datapoints']:
                        if (r['Sum']) == 0:
                            #print("Not  usable")
                            resourceType.append(getvalue["resourceType"])
                            resourceName.append(getvalue["resourceId"].split(
                                ":")[5].split("/", 1)[1].split("/")[1])
                            reason.append(
                                "Application LoadBalancer is not used")
                            count.append(1)

            if getvalue["resourceType"] == "AWS::ACM::Certificate":
                # print(getvalue["resourceId"])
                certclient = boto3.client('acm')
                try:
                    certresponse = certclient.describe_certificate(
                    CertificateArn=getvalue["resourceId"])
                    if (len(certresponse['Certificate']["InUseBy"])) == 0:
                        resourceType.append(getvalue["resourceType"])
                        resourceName.append(getvalue["resourceId"].split(":")[5])
                        count.append(1)
                        reason.append("Certificate is not used")
                except:
                    print("No data in certificates")
                

            if getvalue["resourceType"] == "AWS::SecretsManager::Secret":
                print(getvalue["resourceId"])
                secreclient = boto3.client('secretsmanager')
                try:
                    secrtresponse = secreclient.describe_secret(
                    SecretId=getvalue["resourceId"])
                    if 'LastAccessedDate' in secrtresponse:
                        delta = endTime.replace(
                            tzinfo=None) - secrtresponse['LastAccessedDate'].replace(tzinfo=None)
                        if (delta.days) > 14:
                            resourceType.append(getvalue["resourceType"])
                            resourceName.append(getvalue["resourceId"].split(":")[6])
                            count.append(1)
                            reason.append("Secret Manager Value is not used")
                    else:
                        resourceType.append(getvalue["resourceType"])
                        resourceName.append(getvalue["resourceId"].split(":")[6])
                        count.append(1)
                        reason.append("Secret Manager Value is not used")
                except:
                    print("No data in secret Manager")
                        

            if getvalue["resourceType"] == "AWS::EC2::NatGateway":
                # print(getvalue["resourceId"])
                MetricName = ["ConnectionEstablishedCount"]
                for metric in MetricName:
                    natmetricresponse = cloudwatchclient.get_metric_statistics(
                        Namespace="AWS/NATGateway",
                        MetricName=metric,
                        Dimensions=[
                            {'Name': 'NatGatewayId',
                                'Value': getvalue["resourceId"]}
                        ],
                        StartTime=datetime.datetime.utcnow() - timedelta(days=30),
                        EndTime=datetime.datetime.utcnow(),
                        Statistics=["Sum"],
                        Period=2592000
                    )
                    # print(natmetricresponse)
                    # metricdata.append(natmetricresponse)
                    for r in natmetricresponse['Datapoints']:
                        if (r['Sum']) == 0:
                            # print("Not  usable natgateway")
                            resourceType.append(getvalue["resourceType"])
                            resourceName.append(getvalue["resourceId"])
                            count.append(1)
                            reason.append("NAT Gateway is not used")

            if getvalue["resourceType"] == "AWS::SNS::Topic":
                #print(getvalue["resourceId"])
                #print(getvalue["resourceId"].split(":")[5])
                MetricName = ["NumberOfMessagesPublished"]
                for metric in MetricName:
                    snsmetricresponse = cloudwatchclient.get_metric_statistics(
                        Namespace="AWS/SNS",
                        MetricName=metric,
                        Dimensions=[
                            {'Name': 'TopicName',
                                'Value': getvalue["resourceId"].split(":")[5]}
                        ],
                        StartTime=startTime,
                        EndTime=endTime,
                        Statistics=["Sum"],
                        Period=seconds_in_one_day
                    )
                    # print(snsmetricresponse)
                    # metricdata.append(snsmetricresponse)
                    for r in snsmetricresponse['Datapoints']:
                        if (r['Sum']) == 0:
                            # print("Not  usable natgateway")
                            resourceType.append(getvalue["resourceType"])
                            resourceName.append(
                                getvalue["resourceId"].split(":")[5])
                            count.append(1)
                            reason.append("SNS is not used")

            if getvalue["resourceType"] == "AWS::SQS::Queue":
                #print(getvalue["resourceId"])
                #print(getvalue["resourceName"])
                MetricName = ["NumberOfMessagesReceived"]
                for metric in MetricName:
                    sqsmetricresponse = cloudwatchclient.get_metric_statistics(
                        Namespace="AWS/SQS",
                        MetricName=metric,
                        Dimensions=[
                            {'Name': 'QueueName',
                                'Value': getvalue["resourceName"]}
                        ],
                        StartTime=startTime,
                        EndTime=endTime,
                        Statistics=["Sum"],
                        Period=seconds_in_one_day
                    )
                    # print(sqsmetricresponse)
                    # metricdata.append(sqsmetricresponse)
                    for r in sqsmetricresponse['Datapoints']:
                        if (r['Sum']) == 0:
                            # print("Not  usable natgateway")
                            resourceType.append(getvalue["resourceType"])
                            resourceName.append(
                                getvalue["resourceName"])
                            count.append(1)
                            reason.append("SQS is not used")

            if getvalue["resourceType"] == "AWS::CodePipeline::Pipeline":
                # print(getvalue["resourceId"])
                pipelineclient = boto3.client('codepipeline')
                try:
                    pipelineresponse = pipelineclient.list_pipeline_executions(
                    pipelineName=getvalue["resourceId"])
                    cpdelta = endTime.replace(
                        tzinfo=None) - pipelineresponse["pipelineExecutionSummaries"][0]["lastUpdateTime"].replace(tzinfo=None)
                    if (cpdelta.days) > 14:
                        resourceType.append(getvalue["resourceType"])
                        resourceName.append(getvalue["resourceId"])
                        count.append(1)
                        reason.append("Pipeline is not used")
                except:
                    print("No data in pipeline")
                

            if getvalue["resourceType"] == "AWS::CodeBuild::Project":
                # print(getvalue["resourceId"])
                cbclient = boto3.client('codebuild')
                try:
                    cbresponse = cbclient.list_builds_for_project(
                    projectName=getvalue["resourceName"], sortOrder='DESCENDING')
                    cbbuildresponse = cbclient.batch_get_builds(
                        ids=[cbresponse["ids"][0]])
                    cbdelta = endTime.replace(
                        tzinfo=None) - cbbuildresponse["builds"][0]["startTime"].replace(tzinfo=None)
                    if (cbdelta.days) > 14:
                        resourceType.append(getvalue["resourceType"])
                        resourceName.append(getvalue["resourceName"])
                        count.append(1)
                        reason.append("Code Build is not used")
                except:
                    print("No data in code build")
                

            if getvalue["resourceType"] == "AWS::EC2::Instance":
                #print("Instance")
                #print(getvalue["resourceId"])
                MetricName = ["CPUUtilization"]
                for metric in MetricName:
                    instancemetricresponse = cloudwatchclient.get_metric_statistics(
                        Namespace="AWS/EC2",
                        MetricName=metric,
                        Dimensions=[
                            {'Name': 'InstanceId',
                                'Value': getvalue["resourceId"]}
                        ],
                        StartTime=datetime.datetime.utcnow() - timedelta(days=7),
                        EndTime=datetime.datetime.utcnow(),
                        Statistics=["Average"],
                        Period=3600  #604800
                    )
                    # print(instancemetricresponse)
                    # metricdata.append(instancemetricresponse)
                    average = 0
                    #print(len(instancemetricresponse['Datapoints']))
                    for r in instancemetricresponse['Datapoints']:
                        average = average + r['Average']
                    #print("average: " ,average)    
                    # print(average)    
                    if (round(average,2)) < 60:
                        resourceType.append(getvalue["resourceType"])
                        resourceName.append(getvalue["resourceId"])
                        count.append(1)
                        reason.append("EC2 Instance is underutilized")  

            if getvalue["resourceType"] == "AWS::Lambda::Function":
                # print(getvalue["resourceId"])
                MetricName = ["Invocations"]
                for metric in MetricName:
                    lambdametricresponse = cloudwatchclient.get_metric_statistics(
                        Namespace="AWS/Lambda",
                        MetricName=metric,
                        Dimensions=[
                            {'Name': 'FunctionName',
                                'Value': getvalue["resourceName"]}
                        ],
                        StartTime=startTime,
                        EndTime=endTime,
                        Statistics=["Average"],
                        Period=seconds_in_one_day
                    )
                    # print(lambdametricresponse)
                    if len(lambdametricresponse['Datapoints']) == 0:
                        resourceType.append(getvalue["resourceType"])
                        resourceName.append(getvalue["resourceName"])
                        count.append(1)
                        reason.append("Lambda is not used")
                        lmdclient = boto3.client('lambda')
                        lmdresponse = lmdclient.get_function(FunctionName=getvalue["resourceName"])
                        lmdresourceType.append(getvalue["resourceType"])
                        lmdresourceName.append(getvalue["resourceName"])
                        lmdpackagesize.append(convert_bytes(lmdresponse['Configuration']['CodeSize']))

            if getvalue["resourceType"] == "AWS::RDS::DBCluster":
                # print(getvalue["resourceId"])
                MetricName = ["DatabaseConnections"]
                for metric in MetricName:
                    rdsmetricresponse = cloudwatchclient.get_metric_statistics(
                        Namespace="AWS/RDS",
                        MetricName=metric,
                        Dimensions=[
                            {'Name': 'DBClusterIdentifier',
                                'Value': getvalue["resourceName"]}
                        ],
                        StartTime=startTime,
                        EndTime=endTime,
                        Statistics=["Average"],
                        Period=seconds_in_one_day
                    )
                    # print(rdsmetricresponse)
                    for r in rdsmetricresponse['Datapoints']:
                        if (r['Average']) == 0:
                            # print("Not  usable natgateway")
                            resourceType.append(getvalue["resourceType"])
                            resourceName.append(
                                getvalue["resourceName"])
                            count.append(1)
                            reason.append("DB Cluster is not used")                     
    
            if getvalue["resourceType"] == "AWS::ApiGateway::RestApi" or getvalue["resourceType"] == "AWS::ApiGatewayV2::Api" :
                # print(getvalue["resourceId"])
                MetricName = ["Count"]
                for metric in MetricName:
                    apimetricresponse = cloudwatchclient.get_metric_statistics(
                        Namespace="AWS/ApiGateway",
                        MetricName=metric,
                        Dimensions=[
                            {'Name': 'ApiName',
                                'Value': getvalue["resourceName"]}
                        ],
                        StartTime=startTime,
                        EndTime=endTime,
                        Statistics=["Average"],
                        Period=seconds_in_one_day
                    )
                    # print(apimetricresponse)
                    if len(apimetricresponse['Datapoints']) == 0:
                        resourceType.append(getvalue["resourceType"])
                        resourceName.append(getvalue["resourceName"])
                        count.append(1)
                        reason.append("Api Gateway is not used")

            if getvalue["resourceType"] == "AWS::S3::Bucket":
                # print(getvalue["resourceId"])
                s3client = boto3.client('s3')
                s3objects = []
                size = 0
                try:
                    s3response = s3client.list_objects(
                    Bucket=getvalue["resourceName"])
                    if 'Contents' in s3response:
                        for data in s3response['Contents']:
                            s3objects.append(data['LastModified'])
                            size = size + data['Size']
                        #if s3response['IsTruncated'] == True:
                        # while('IsTruncated' == True in s3response):
                        #     s3response = s3client.list_objects(
                        #         Bucket=getvalue["resourceName"] ,Marker=s3response['Key'])
                        #     for data in s3response['Contents']:
                        #         s3objects.append(data['LastModified'])
                        s3delta = endTime.replace(
                            tzinfo=None) - sorted(s3objects,reverse=True)[0].replace(tzinfo=None)
                        if (s3delta.days) > 14:
                            resourceType.append(getvalue["resourceType"])
                            resourceName.append(getvalue["resourceName"])
                            count.append(1)
                            reason.append("S3 is not used")
                            s3resourceType.append(getvalue["resourceType"])
                            s3resourceName.append(getvalue["resourceName"])
                            s3size.append(convert_bytes(size))
                            # s3metricresponse = cloudwatchclient.get_metric_statistics(
                            #     Namespace="AWS/S3",
                            #     MetricName='BucketSizeBytes',
                            #     Dimensions=[
                            #         {'Name': 'BucketName','Value': getvalue["resourceName"]},
                            #         {'Name':'StorageType','Value': s3response['Contents'][0]['StorageClass']  + 'Storage'}
                            #     ],
                            #     StartTime=startTime,
                            #     EndTime=endTime,
                            #     Statistics=["Average"],
                            #     Period=seconds_in_one_day
                            # )
                            # for r in s3metricresponse['Datapoints']:
                            #     s3resourceType.append(getvalue["resourceType"])
                            #     s3resourceName.append(getvalue["resourceName"])
                            #     s3size.append(convert_bytes(r['Average']))
                    else:
                        resourceType.append(getvalue["resourceType"])
                        resourceName.append(getvalue["resourceName"])
                        count.append(1)
                        reason.append("S3 is not used")
                        s3resourceType.append(getvalue["resourceType"])
                        s3resourceName.append(getvalue["resourceName"])
                        s3size.append("0 B")
                except:
                    print("No data in S3 Bucket")
    # print(resources)

    dataset = {
        'resourceType': resourceType,
        'resourceName': resourceName,
        'reason': reason,
        'count': count
    }

    cwdataset = {
        'resourceType': cwresourceType,
        'resourceName': cwresourceName,
        'reason': cwreason
    }

    lmddataset = {
        'resourceType': lmdresourceType,
        'resourceName': lmdresourceName,
        'reason': lmdpackagesize
    }

    s3dataset = {
        'resourceType': s3resourceType,
        'resourceName': s3resourceName,
        'reason': s3size
    }

    cwdf = pd.DataFrame.from_dict(cwdataset)
    cw_result_table = data_table(cwdf,'Reason')

    lmddf = pd.DataFrame.from_dict(lmddataset)
    lmd_result_table = data_table(lmddf,'Size')

    s3df = pd.DataFrame.from_dict(s3dataset)
    s3_result_table = data_table(s3df,'Size')

    df = pd.DataFrame.from_dict(dataset)
    result_table = data_table(df,'Reason')
    bar_resources = bar_totals(df, 'resourceType')

    BODY_HTML = "<p><table><td><font color='blue'>Breakdown by AWS service</font><br>{}</td></table></p>"
    BODY_HTML = BODY_HTML.format(bar_resources)
    BODY_HTML += "<p><H2><font color='blue'>All Resources:</font> <H2></p><p>{}</p>"
    BODY_HTML = BODY_HTML.format(result_table)
    # BODY_HTML += result_table

    #print(lmd_result_table)
    BODY_HTML += "<p><H2><font color='blue'>Lambda Unused Code Size:</font> <H2></p><p>{}</p>"
    BODY_HTML = BODY_HTML.format(lmd_result_table)

    BODY_HTML += "<p><H2><font color='blue'>S3 Unused Bucket Size:</font> <H2></p><p>{}</p>"
    BODY_HTML = BODY_HTML.format(s3_result_table)
    
    BODY_HTML += "<p><H2><font color='blue'>CloudWatch Log Groups:</font> <H2></p><p>{}</p>"
    BODY_HTML = BODY_HTML.format(cw_result_table)

    res = send_mail(BODY_HTML, startTime, endTime)
    # res = send_mail(result_table, startTime, endTime)

    return {
        'statusCode': 200,
        'body': json.dumps(res)
    }


def send_mail(table, startTime, endTime):
    SENDER = os.environ['sender']
    #print(SENDER)
    RECIPIENT = os.environ['receiver']
    #print(RECIPIENT)
    CONFIGURATION_SET = "ConfigSet"
    SUBJECT = "Un-used AWS Resources in "+ os.environ['app'] +" "+ \
        os.environ['env'] + " environment"
    BODY_TEXT = ("Amazon SES Test (Python)\r\n"
                 "This email was sent with Amazon SES using the "
                 "AWS SDK for Python (Boto).")

    CHARSET = "UTF-8"
    BODY_HTML = "<H1>AWS Un-used Resources in " + \
        os.environ['env'] + \
        " environment <font color='blue'>from {} to {} </font></H1><br>"
    BODY_HTML += table
    BODY_HTML = BODY_HTML.format(startTime.strftime(
        '%d-%m-%Y'), endTime.strftime('%d-%m-%Y'))
    sesclient = boto3.client('ses')

    # Try to send the email.
    try:
        # Provide the contents of the email.
        response = sesclient.send_email(
            Destination={
                'ToAddresses': [
                    RECIPIENT,
                ],
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': CHARSET,
                        'Data': BODY_HTML,
                    },
                    'Text': {
                        'Charset': CHARSET,
                        'Data': BODY_TEXT,
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': SUBJECT,
                },
            },
            Source=SENDER,
            # If you are not using a configuration set, comment or delete the
            # following line
            # ConfigurationSetName=CONFIGURATION_SET,
        )
    # Display an error if something goes wrong.
    except ClientError as e:
        print(e.response['Error']['Message'])
        return "Error"
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])
        return "Success"


def bar_totals(df, grouping_col):
    df_grouped = df.groupby([grouping_col])['count'].sum().reset_index(
        name='total_count').sort_values(by=['total_count'], ascending=False)
    df_grouped['total_count'] = df_grouped['total_count']
    chli = return_total_count(df)
    chd = ''
    chl = ''
    chdl = ''
    for index, row in df_grouped.iterrows():
        chd += '{}|'.format(row['total_count'])
        chdl += '{}({})|'.format(row[grouping_col], row['total_count'])
    bar_chart = '<p><img src="https://image-charts.com/chart?cht=bvg&chs=700x400&chd=t:{}&chdl={}&chds=a"> </p>'.format(
        chd[:-3], chdl[:-1])
    return bar_chart


def return_total_count(df):
    df_total = df['count'].sum().round(3)
    result = '{}'.format(df_total)
    return result

def convert_bytes(num):
    step_unit = 1000.0 #1024 bad the size
    for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if num < step_unit:
            return "%3.1f %s" % (num, x)
        num /= step_unit