import boto3
from botocore.exceptions import ClientError
from jira import JIRA
from jira import JIRAError
import json
import os

jira_user = os.environ["jira_user"]
jira_token = os.environ["jira_token"]

# set using the get_aws_account() function
api_key = None
api_secret = None

# infra key set using the get_aws_account() function
infra_key = None
infra_secret = None

# api key id (used to retrieve api key name from agi gateway)
apigateway_api_key_id = None

def lambda_handler(event, context):
    # print("Received event: " + json.dumps(event, indent=2))
    print("Log stream name:", context.log_stream_name)
    print("Log group name:",  context.log_group_name)
    print("Request ID:", context.aws_request_id)
    print("Mem. limits(MB):", context.memory_limit_in_mb)
    # Code will execute quickly, so we add a 1 second intentional delay so you can see that in time remaining value.
    print("Time remaining (MS):", context.get_remaining_time_in_millis())

    # get account's api key and secret using aws_account passed in as argument
    try:
        # api key id for api gateway user key
        global apigateway_api_key_id
        apigateway_api_key_id = event['requestContext']['identity']['apiKeyId']

        body_values = json.loads(event['body'])
        # response is { api_key : api_secret } dict
        get_aws_account_response = get_aws_account_creds(body_values['aws_account'])
        # modify globals
        global api_key
        api_key = next(iter(get_aws_account_response.keys()))
        global api_secret
        api_secret = next(iter(get_aws_account_response.values()))

    except ClientError as e:
        print("ClientError: ", e.response)
        return {
            'statusCode': 500,
            'body': json.dumps("ClientError: {}".format(str(e.response))),
            'headers': {'Content-Type': 'application/json'}
        }
    except Exception as e:
        print("Exception: ", e)
        return {
            'statusCode': 500,
            'body': json.dumps("Exception: {}".format(str(e))),
            'headers': {'Content-Type': 'application/json'}
        }


    try:
        if event['httpMethod'] == 'GET':
            print("GET method")
            # body values passed in
            body_values = json.loads(event['body'])
            secgroup_id = body_values['secgroup_id']
            region = body_values["region"]

            # get sec group rules
            sec_group_rules_response = get_rules(region=region, secgroup_id=secgroup_id)

            return {
                'statusCode': 200,
                'body': json.dumps("{}".format(sec_group_rules_response)),
                'headers': {'Content-Type': 'application/json'}
            }


        if event['httpMethod'] == 'DELETE':
            print("DELETE method")
            # body values passed in
            body_values = json.loads(event['body'])

            user = body_values["user"]
            region = body_values["region"]
            secgroup_id = body_values["secgroup_id"]
            protocol = body_values["protocol"]
            cidr_ip = body_values["cidr_ip"]
            port = int(body_values["port"])
            sor_ticket = body_values["sor_ticket"]

            remove_rule_response = remove_rule(user=user, region=region, secgroup_id=secgroup_id, protocol=protocol, cidr_ip=cidr_ip, port=port, sor_ticket=sor_ticket)

            return {
                'statusCode': 200,
                'body': json.dumps("{}".format(str(remove_rule_response))),
                'headers': {'Content-Type': 'application/json'}
            }


        if event['httpMethod'] == 'POST':
            print("POST method")
            # body values passed in
            body_values = json.loads(event['body'])

            user = body_values["user"]
            region = body_values["region"]
            secgroup_id = body_values["secgroup_id"]
            protocol = body_values["protocol"]
            cidr_ip = body_values["cidr_ip"]
            port = int(body_values["port"])
            sor_ticket = body_values["sor_ticket"]

            add_rule_response = add_rule(user=user, region=region, secgroup_id=secgroup_id, protocol=protocol, cidr_ip=cidr_ip, port=port, sor_ticket=sor_ticket)

            return {
                    'statusCode': 200,
                    'body': json.dumps("{}".format(str(add_rule_response))),
                    'headers': {'Content-Type': 'application/json'}
                }

    except KeyError as e:
        return {
            'statusCode': 500,
            'body': json.dumps("KeyError: check that this request has the correct parameter and argument for: {}".format(str(e))),
            'headers': {'Content-Type': 'application/json'}
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps("Exception in Lambda Handler: {}".format(str(e))),
            'headers': {'Content-Type': 'application/json'}
        }


# takes in aws account argument from user
def get_aws_account_creds(aws_account):
    accounts = {}

    # customer1 creds
    customer1_key = os.environ["customer1_key"]
    customer1_secret = os.environ["customer1_secret"]
    accounts['symphony-aws-customer1'] = {customer1_key: customer1_secret}

    # customer 2 creds
    customer2_key = os.environ["customer2_key"]
    customer2_secret = os.environ["customer2_secret"]
    accounts['symphony-aws-customer2'] = {customer2_key: customer2_secret}

    # infra creds
    global infra_key
    infra_key = os.environ["infra_key"]
    global infra_secret
    infra_secret = os.environ["infra_secret"]
    accounts['symphony-aws-infra'] = {infra_key: infra_secret}

    return accounts[aws_account]



def jira_ticket_add_comment(user, action, secgroup_id, protocol, cidr_ip, port, sor_ticket):

    jira_api_url = "https://perzoinc.atlassian.net"
    jira = JIRA(jira_api_url, basic_auth=(jira_user, jira_token))

    issue = jira.issue(sor_ticket)
    issue_comment = "{} {} rule {} \nPort: {}\nProtocol: {}\n Security Group ID: {}".format(user, action, cidr_ip, port, protocol, secgroup_id)
    jira_response = jira.add_comment(issue, issue_comment)

    print("Jira response: {} {} rule {} Port: {}, Protocol: {}, Security Group ID: {}".format(user, action, cidr_ip, port, protocol, secgroup_id))
    return "Jira response: {} {} rule {} Port: {}, Protocol: {}, Security Group ID: {}".format(user, action, cidr_ip, port, protocol, secgroup_id)



def get_boto_resource(region, service, secgroup_id):

    ec2 = boto3.resource(
        service,
        region_name=region,
        aws_access_key_id=api_key,
        aws_secret_access_key=api_secret,
    )
    security_group = ec2.SecurityGroup(secgroup_id)
    return security_group



def get_boto_client(region, service):

    boto_client = boto3.client(
        service,
        region_name=region,
        aws_access_key_id=api_key,
        aws_secret_access_key=api_secret,
    )
    return boto_client


# get api key name for user key from api gateway
def get_apigateway_api_key_name(apiKeyId):

    try:
        boto_client = boto3.client(
            'apigateway',
            region_name='us-east-1',
            aws_access_key_id=str(infra_key),
            aws_secret_access_key=str(infra_secret),
        )
        get_api_key_response = boto_client.get_api_key(
            apiKey=str(apiKeyId),
            includeValue=False
        )
    except ClientError as e:
        print("Client Error: {}".format(str(e)))
        return "Client Error: {}".format(str(e))

    return str(get_api_key_response['name'])



# checks if sec group is 443/8444 or 22(sftp) sec group
def check_allowed_secgroup(region, secgroup_id):

    sec_group_boto_client = get_boto_client(region=region, service='ec2')

    group_name = "empty security group name"

    try:
        response = sec_group_boto_client.describe_security_groups(GroupIds=[secgroup_id])
        group_name = str(response['SecurityGroups'][0]['GroupName']).lower()
    except ClientError as e:
        print("Client Error: {}".format(str(e.response)))
        return "Client Error: {}".format(str(e.response))

    print("Security group name: {}".format(group_name))

    # checks for correct sec group
    if (('sftp' in group_name) or ('443' in group_name) or ('8444' in group_name)):
        if ('4432407' not in group_name) and ('443_2407' not in group_name) and ('443mds' not in group_name):
            # print("Correct sec group")
            return True
        else:
            # print("Incorrect sec group")
            return False
    else:
        # print("Incorrect sec group")
        return False



def get_rules(region, secgroup_id):
    sec_group_boto_client = get_boto_client(region=region, service='ec2')

    try:
        response = sec_group_boto_client.describe_security_groups(GroupIds=[secgroup_id])
        sec_group_rules = response['SecurityGroups'][0]['IpPermissions']
        print(sec_group_rules)
        return sec_group_rules

    except ClientError as e:
        print("Client Error: {}".format(str(e.response)))
        return "Client Error: {}".format(str(e.response))


def remove_rule(user, region, secgroup_id, protocol, cidr_ip, port, sor_ticket):

    # ensure correct ticket number is added
    if str(sor_ticket).startswith('SOR-'):
        pass
    else:
        print("Failed: Description argument needs to start with 'SOR-'")
        return "Failed: Description argument needs to start with 'SOR-'"

    # True if yes, False if no
    allowed_to_modify = check_allowed_secgroup(region=region, secgroup_id=secgroup_id)
    print("Allowed to modify sec group: {}".format(allowed_to_modify))

    apigateway_key_name = get_apigateway_api_key_name(apigateway_api_key_id)

    # can only modify following ports (standard, api or sftp)
    if ((port == 443 or port == 8444 or port == 22) and (allowed_to_modify)):
        try:
            # jira_response = jira_ticket_add_comment(user, "removed", secgroup_id, protocol, cidr_ip, port, sor_ticket)

            sec_group_boto_resource = get_boto_resource(region=region, service='ec2', secgroup_id=secgroup_id)

            response = sec_group_boto_resource.revoke_ingress(
                IpProtocol=protocol,
                CidrIp=cidr_ip,
                FromPort=port,
                ToPort=port,
                DryRun=False
            )

            print("Successfully removed rule; user: {} ({}), cidr: {}, port: {}, protocol: {}, security group: {}, ticket {}".format(user, apigateway_key_name, cidr_ip, port, protocol, secgroup_id, sor_ticket))
            return "Successfully removed rule; user: {} ({}), cidr: {}, port: {}, protocol: {}, security group: {}, ticket {}".format(user, apigateway_key_name, cidr_ip, port, protocol, secgroup_id, sor_ticket)
        except JIRAError as je:
            print("Jira: failed adding comment " + je.text)
            return "Jira: failed adding comment " + je.text
        except ClientError as e:
            print("Client Error: {}".format(str(e.response)))
            return "Client Error: {}".format(str(e.response))
        except Exception as e:
            print("Exception: {}".format(str(e)))
            return "Exception: {}".format(str(e))
    else:
        print("Failed: Not allowed to modify. Check allowed ports and ensure you're allowed to modify this security group")
        return "Failed: Not allowed to modify. Check allowed ports and ensure you're allowed to modify this security group"





def add_rule(user, region, secgroup_id, protocol, cidr_ip, port, sor_ticket):

    if str(sor_ticket).startswith('SOR-'):
        pass
    else:
        print("Failed: Description argument needs to start with 'SOR-'")
        return "Failed: Description argument needs to start with 'SOR-'"

    # True if yes, False if no
    allowed_to_modify = check_allowed_secgroup(region=region, secgroup_id=secgroup_id)
    print("Allowed to modify sec group: {}".format(allowed_to_modify))

    apigateway_key_name = get_apigateway_api_key_name(apigateway_api_key_id)

    # can only modify following ports (standard, api or sftp)
    if ((port == 443 or port == 8444 or port == 22) and (allowed_to_modify)):

        try:
            # jira_response = jira_ticket_add_comment(user, "added", secgroup_id, protocol, cidr_ip, port, sor_ticket)

            sec_group_boto_resource = get_boto_resource(region=region, service='ec2', secgroup_id=secgroup_id)

            response = sec_group_boto_resource.authorize_ingress(
                IpPermissions=[
                    {
                        'FromPort': port,
                        'IpProtocol': protocol,
                        'IpRanges': [
                            {
                                'CidrIp': cidr_ip,
                                'Description': sor_ticket
                            },
                        ],
                        'ToPort': port,
                    },
                ],
                DryRun=False
            )

            print("Successfully added rule; user: {} ({}), cidr: {}, port: {}, protocol: {}, security group: {}, ticket {}".format(user, apigateway_key_name, cidr_ip, port, protocol, secgroup_id, sor_ticket))
            return "Successfully added rule; user: {} ({}), cidr: {}, port: {}, protocol: {}, security group: {}, ticket {}".format(user, apigateway_key_name, cidr_ip, port, protocol, secgroup_id, sor_ticket)
        except JIRAError as je:
            print("Jira: failed adding comment " + je.text)
            return "Jira: failed adding comment " + je.text
        except ClientError as e:
            print("Client Error: {}".format(str(e)))
            return "Client Error: {}".format(str(e))
        except Exception as e:
            print("Exception: {}".format(str(e)))
            return "Exception: {}".format(str(e))

    else:
        print("Failed: Not allowed to modify. Check allowed ports and ensure you're allowed to modify this security group")
        return "Failed: Not allowed to modify. Check allowed ports and ensure you're allowed to modify this security group"

