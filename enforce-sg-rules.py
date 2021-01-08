#!/usr/bin/python

import boto
import boto3
from boto import ec2

import yaml


#client = boto3.client('ec2', region_name='us-east-1',aws_access_key_id='XXXXXXXXXXXXXXX',aws_secret_access_key='XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')


client = boto3.client('ec2', region_name='us-east-1')

with open(r'SecurityGroups.yaml') as file:
  localSGs = yaml.load(file, Loader=yaml.FullLoader)
ruleFound=False

for sg in localSGs['SecurityGroups']:

    print ("Checking security group: " , sg['GroupId'])

    
    awsSGs = client.describe_security_groups(GroupIds=[sg['GroupId']])
    
    #awsSGs =yaml.safe_dump(response,  default_flow_style=False)
    
    # print (awsSGs)

    for localRule in sg['IpPermissions']:
        print ("\nChecking if the rule exists:" , localRule, "\n")
        ruleFound=False

    
        for awsSG in awsSGs['SecurityGroups']:
            for awsRule in awsSG['IpPermissions']:

                print ("AWS rule: ", awsRule)
                if localRule == awsRule:
                    print ("\nThe rule has been found in the AWS SG\n")
                    ruleFound=True
                    break

       
        if ruleFound != True: 
            print ("The rule was not found in the AWS SG, trying to create missing rule...")
            print (localRule)
            data = client.authorize_security_group_ingress(
                   GroupId=sg['GroupId'],
                   DryRun=False,
                   IpPermissions=[localRule]
            )