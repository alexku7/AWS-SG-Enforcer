#!/usr/bin/python

import boto
import boto3
from boto import ec2

import yaml


#client = boto3.client('ec2', region_name='us-east-1',aws_access_key_id='XXXXXXXXXXXXXXX',aws_secret_access_key='XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')


client = boto3.client('ec2', region_name='us-east-1')

# Load yaml file with the SG defintions 
with open(r'SecurityGroups.yaml') as file:
  localSGs = yaml.load(file, Loader=yaml.FullLoader)

ruleFound=False

# Go through the SG list in the YAML definition file
for sg in localSGs['SecurityGroups']:
    print ("Checking security group: " , sg['GroupId'])

    # get SG rules from AWS  
    awsSGs = client.describe_security_groups(GroupIds=[sg['GroupId']])

# Go through the AWS SG rules and find rules which don't exist in the YAML file. Delete rules if needed form the SG 
    for awsSG in awsSGs['SecurityGroups']:
        for awsRule in awsSG['IpPermissions']:
            print ("\nChecking if the AWS SG ingress rule exists in local YAML file:\n" , awsRule, "\n")
            ruleFound=False

            for localRule in sg['IpPermissions']:
                 print ("Local rule: ", localRule)
                 if localRule == awsRule:
                    print ("\nThe ingress rule has been found in local YAML file \n")
                    ruleFound=True
                    break   
       # If rule was not found , remove it from the AWS SG
        if ruleFound != True: 
            print ("\nThe ingress rule was not found in the local YAML, delete the illegal rule ...\n")
            print (awsRule)
            data = client.revoke_security_group_ingress(
                   GroupId=sg['GroupId'],
                   DryRun=False,
                   IpPermissions=[awsRule]
            )
        ruleFound=False
        for awsRule in awsSG['IpPermissionsEgress']:
            print ("\nChecking if the AWS SG Egress rule exists in local YAML file:\n" , awsRule, "\n")
            ruleFound=False

            for localRule in sg['IpPermissionsEgress']:
                 print ("Local rule: ", localRule)
                 if localRule == awsRule:
                    print ("\nThe Egress rule has been found in local YAML file \n")
                    ruleFound=True
                    break   
       # If rule was not found , remove it from the AWS SG
        if ruleFound != True: 
            print ("\nThe Egress rule was not found in the local YAML, delete the illegal rule ...\n")
            print (awsRule)
            data = client.revoke_security_group_egress(
                   GroupId=sg['GroupId'],
                   DryRun=False,
                   IpPermissions=[awsRule]
            )


    # Go through the rules in the yaml file and compare them with the existing rules in AWS SG
    for localRule in sg['IpPermissions']:
        print ("\nChecking if the local ingress rule exists in the AWS SG:\n" , localRule, "\n")
        ruleFound=False
    
        for awsSG in awsSGs['SecurityGroups']:
            for awsRule in awsSG['IpPermissions']:
                print ("AWS rule: ", awsRule)
                if localRule == awsRule:
                    print ("\nThe ingress rule has been found in the AWS SG\n")
                    ruleFound=True
                    break

       # If rule was not found , add it to the SG
        if ruleFound != True: 
            print ("The ingress rule was not found in the AWS SG, trying to create missing rule...")
            print (localRule)
            data = client.authorize_security_group_ingress(
                   GroupId=sg['GroupId'],
                   DryRun=False,
                   IpPermissions=[localRule]
            )

    for localRule in sg['IpPermissionsEgress']:
        print ("\nChecking if the local Egress rule exists in the AWS SG:\n" , localRule, "\n")
        ruleFound=False
    
        for awsSG in awsSGs['SecurityGroups']:
            for awsRule in awsSG['IpPermissionsEgress']:
                print ("AWS rule: ", awsRule)
                if localRule == awsRule:
                    print ("\nThe Egress rule has been found in the AWS SG\n")
                    ruleFound=True
                    break

       # If rule was not found , add it to the SG
        if ruleFound != True: 
            print ("The Egress rule was not found in the AWS SG, trying to create missing rule...")
            print (localRule)
            data = client.authorize_security_group_egress(
                   GroupId=sg['GroupId'],
                   DryRun=False,
                   IpPermissions=[localRule]
            )    