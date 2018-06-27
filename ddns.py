def lambda_handler(event, context):
    """ Find all instances with tag:DNS and create Route 53 A record based on the tag value."""
    __author__ = "Dao Che"
    __copyright__ = "2017-11-1,  Hobby project"
    __status__ = "Dev"
    
    import re
    import boto3
    import botocore
    
    DDB_CLIENT = boto3.client('dynamodb')
    DDB_RESOURCE = boto3.resource('dynamodb')
    
    PRIVATE_ZONE_ID = ""
    PUBLIC_ZONE_ID = ""
    PRIVATE_ZONE_NAME = "aws.my.domain.com"
    PUBLIC_ZONE_NAME = "aws.my.domain.com"       # PUBLIC and PRIVATE zones use the same name.
    
    
    def get_instance_by_tag(tag_key, tag_value):
        """ Search all instances with tag:DNS """
        instance = EC2.describe_instances(
            Filters=[
                {
                    'Name': 'tag:' + tag_key,
                    'Values': [tag_value]
                }
            ]
        )
    
        # Return instance IDs.
        instance_ids = []
        for xxx in instance['Reservations']:
            for yyy in xxx['Instances']:
                instance_ids.append(yyy['InstanceId'])
        return instance_ids
    
    
    def create_resource_record(zone_id, hosted_zone_name, host_name, dns_type, resource_record):
        """ Create resource records in hosted zones """
        if re.search(r"\.", host_name) is None:
            host_name = host_name + '.' + hosted_zone_name
    
        print('{:5s} {:50s} {:20s}  - created.'.format(dns_type, host_name, resource_record))
    
        ROUTE53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Comment": "Update by instance tag:DNS",
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": {
                                "Name": host_name,
                                "Type": dns_type,
                                "TTL": 60,
                                "ResourceRecords": [
                                    {
                                        "Value": resource_record
                                    }
                                ]
                            }
                        }
                    ]
                }
        )
    
    
    
    def delete_resource_record(zone_id, hosted_zone_name, host_name, dns_type, resource_record):
        """ Delete resource records in hosted zones"""
        if re.search(r"\.", host_name) is None:
            host_name = host_name + '.' + hosted_zone_name
    
        print('{:5s} {:50s} {:20s} - deleted.'.format(dns_type, host_name, resource_record))
    
        try:
            ROUTE53.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch={
                    "Comment": "Updated by Lambda DDNS",
                    "Changes": [
                        {
                            "Action": "DELETE",
                            "ResourceRecordSet": {
                                "Name": host_name,
                                "Type": dns_type,
                                "TTL": 60,
                                "ResourceRecords": [
                                    {
                                        "Value": resource_record
                                    },
                                ]
                            }
                        },
                    ]
                }
            )
        except botocore.exceptions.ClientError as e:
            print(e)
            print("Error - something happened " + hosted_zone_name + " " + host_name + " " + resource_record)
            pass
    
    
    def create_table(table_name):
        """ Creat DynamoDB table with Read and Write capacity set to minimum 1.
            Use autoscalling outside of this routine to scale capacity.
        """
        DDB_CLIENT.create_table(
            TableName=table_name,
            AttributeDefinitions=[
                {
                    'AttributeName': 'InstanceId',
                    'AttributeType': 'S'
                },
            ],
            KeySchema=[
                {
                    'AttributeName': 'InstanceId',
                    'KeyType': 'HASH'
                },
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 1,
                'WriteCapacityUnits': 1
            }
        )
        table = DDB_RESOURCE.Table(table_name)
        table.wait_until_exists()
    
    
    def get_ec2_properties(instance_id):
        """ Get ec2 instance properties"""
        ec2 = {}       # stores ec2 properties
        instance = EC2.describe_instances(InstanceIds=[instance_id])
        state = instance['Reservations'][0]['Instances'][0]['State']['Name']
    
        ec2['instance_id'] = instance_id
        ec2['state'] = state
    
        tags = instance['Reservations'][0]['Instances'][0]['Tags']
        ec2['name'] = get_dns_tag(tags)
    
    
        ec2['name'] = get_dns_tag(tags)
        try:
            ec2['ip'] = instance['Reservations'][0]['Instances'][0]['PrivateIpAddress']
        except KeyError:
            ec2['ip'] = ''
        try:
            ec2['public_ip'] = instance['Reservations'][0]['Instances'][0]['PublicIpAddress']
        except KeyError:
            ec2['public_ip'] = ''
    
        return ec2
    
    
    def get_dns_tag(tags):
        """ Search tag key: DDNS and return the tag value"""
        name = ''
        for host in tags:
            if host['Key'] == "DNS":
                name = host['Value']
                return name
    
    
    
    
    def get_ec2(ddns_table, instance_id):
        """ Check if the instance exists in the DynamoDB table. """
        ec2 = {}
        ddns = ddns_table.get_item(
            Key={
                'InstanceId': instance_id
            },
            AttributesToGet=[
                'DDNS',
                'Value',
            ]
        )
        try:
            ec2['name'] = ddns['Item']['DDNS']
            ec2['ip'] = ddns['Item']['Value']
        except KeyError:
            pass
        return ec2
    
    
    def create_dns_resource_record(zone_id, zone_name, ddns_table, instance_id, name, ip):
        """ Search all instances in the account with the tag: "DNS" and update Route53 record sets."""
        old_name = ''
        old_ip = ''
    
        ddns = ddns_table.get_item(
            Key={
                'InstanceId': instance_id
            },
            AttributesToGet=[
                'DDNS',
                'Value',
            ]
        )
        try:
            old_name = ddns['Item']['DDNS']
            # if route53 name exists, do nothing
            if name == old_name:
                return
    
            if re.search(r"\.", old_name) is None:
                old_name = old_name + '.' + zone_name
    
            old_ip = ddns['Item']['Value']
    
            delete_resource_record(zone_id, zone_name, old_name, 'A', old_ip)
            delete_ddns_item(ddns_table, instance_id)
    
        except Exception:
            pass
    
        # create new DNS record
        if ip != '':
            create_resource_record(zone_id, zone_name,
                                    name, 'A', ip)
    
        # update dynamoDB with new name and ip addresses
        ddns_table.put_item(
            Item={
                'InstanceId': instance_id,
                'DDNS': name,
                'Value': ip,
            }
        )
    
    
    def delete_ddns_item(ddns_table, instance_id):
        """ Delete instance from the table when an instance is terminated. """
        try:
            ddns_table.delete_item(
                Key={
                    'InstanceId': instance_id,
                }
            )
        except Exception:
            print("Cannot delete item %s", instance_id)
    
    
    def create_ddns_table(table_name):
        """ find DDNS table, create one if does not exist """
        tables = DDB_CLIENT.list_tables()
        if table_name not in tables['TableNames']:
            create_table(table_name)
    
    
    
    def update_record(ddns_table, zone_id, zone_name, instance_id):
        """ Check if the instance exists in the DynamoDB."""
        ec2 = get_ec2(ddns_table, instance_id)
    
        try:
            dns_name = ec2['name']
            ip = ec2['ip']
            delete_resource_record(zone_id, zone_name, dns_name, 'A', ip)
            delete_ddns_item(ddns_table, instance_id)
        except Exception:
            pass
    
    
    def create_new_record(ddns_table, zone_id, zone_name, instance_id, dns_name, ip):
        """ Check if ec2 instance exist in database and update it if name or ip changes. """
    
    
        try:
            old_ec2 = get_ec2(ddns_table, instance_id)
            # get name and ip from DynamoDB
            old_name = old_ec2['name']
            old_ip = old_ec2['ip']
        except Exception:
            create_dns_resource_record(zone_id, zone_name, ddns_table, instance_id, dns_name, ip)
            return
    
        # if no record found in database or the new name is difference from before, then
        # delete old record from Route53 and database, and then create a new record. 
        if old_name != dns_name or old_ip != ip:
            # remove old record from Route53 first
            delete_resource_record(zone_id, zone_name, old_name, 'A', old_ip)
    
            # then, remove old record from DynamoDB
            delete_ddns_item(ddns_table, instance_id)
    
            # finally, create the record
            create_dns_resource_record(zone_id, zone_name, ddns_table, instance_id, dns_name, ip)
    
    
    # Create DynamoDB tableS if it does not exist.
    create_ddns_table(PRIVATE_ZONE_ID)
    create_ddns_table(PUBLIC_ZONE_ID)
    
    
    def scan_ec2():
        """ Search all instances in the account with the tag: "DNS" and update Route53 record sets."""
        instances = get_instance_by_tag(tag_key="DNS", tag_value="*")
    
        for instance_id in instances:
            ec2 = get_ec2_properties(instance_id)
            dns_name = ec2['name']
            private_ip = ec2['ip']
            public_ip = ec2['public_ip']
            
            if re.search(r"[a-zA-Z0-9][a-zA-Z0-9-_\.]{1,}[a-zA-Z0-9]{1,}", dns_name) is None:
                print("Invalid dns name for host %s %s %s %s", (dns_name, private_ip, public_ip, instance_id))
                continue
    
            if ec2['state'] != 'running':
                # remove record if any from Route53 private zone and from DynamoDB
                zone_id = PRIVATE_ZONE_ID
                zone_name = PRIVATE_ZONE_NAME
                ddns_table = DDB_RESOURCE.Table(zone_id)
                update_record(ddns_table, zone_id, zone_name, instance_id)
    
                # remove record if any from Route53 public zone and from DynamoDB
                zone_id = PUBLIC_ZONE_ID
                zone_name = PUBLIC_ZONE_NAME
                ddns_table = DDB_RESOURCE.Table(zone_id)
                update_record(ddns_table, zone_id, zone_name, instance_id)
                
            else:
                if private_ip != '':
                    zone_id = PRIVATE_ZONE_ID
                    zone_name = PRIVATE_ZONE_NAME
                    ddns_table = DDB_RESOURCE.Table(zone_id)
                    create_new_record(ddns_table, zone_id, zone_name, instance_id, dns_name, private_ip)
    
    
                if public_ip != '':
                    zone_id = PUBLIC_ZONE_ID
                    zone_name = PUBLIC_ZONE_NAME
                    ddns_table = DDB_RESOURCE.Table(zone_id)
                    create_new_record(ddns_table, zone_id, zone_name, instance_id, dns_name, public_ip)
    
    
    # main handlder 
    
    ROUTE53 = boto3.client('route53')
    
    # Process Core account
    EC2 = boto3.client('ec2')
    scan_ec2()
    
    ### The following block of code is intended for cross-accont EC2 update.
    sts_client = boto3.client('sts')
    
    my-account_accounts = ["xxxxxxxx"]
    
    for account in my-account_accounts:
        arn = "arn:aws:iam::" + account + ":role/my-account-ddns-assume-role"
        assumedRoleObject = sts_client.assume_role(RoleArn=arn,RoleSessionName="my-account-ddns-lambda_handler",DurationSeconds=1500)
        credentials = assumedRoleObject['Credentials']
        
        # Describe ec2s in trusting acconts
        EC2 = boto3.client('ec2',
                                aws_access_key_id = credentials['AccessKeyId'],
                                aws_secret_access_key = credentials['SecretAccessKey'],
                                aws_session_token = credentials['SessionToken'],
                                region_name='us-east-2')
        scan_ec2()
