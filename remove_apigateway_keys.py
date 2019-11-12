import boto3
from botocore.exceptions import ClientError
import os
import json


# infra key
api_key = os.environ["infra_api_key"]
api_secret = os.environ["infra_api_secret"]


def lambda_handler(event, context):

    try:
        boto_client = boto3.client(
            'apigateway',
            region_name='us-east-1',
            aws_access_key_id=api_key,
            aws_secret_access_key=api_secret,
        )

        # get all keys
        api_keys_response = boto_client.get_api_keys(
            limit=123,
            includeValues=False
        )

        print("get api keys response: ", api_keys_response['items'])

        # add all the keys that were deleted
        deleted_keys_list = []

        # get each key "item" from the response list
        for item in api_keys_response['items']:
            print('found key with the name: ', item['name'])

            # get each key name and key id
            item_user_key_name = item['name']
            item_user_key_id = item['id']


            # delete api keys whose names start with the following
            if item_user_key_name.startswith('sym-secops-sg-api-'):
                response = boto_client.delete_api_key(
                    apiKey=item_user_key_id
                )

                # attach each deleted key
                deleted_keys_list.append(item_user_key_name)

                print("deleted key's response: \n", response)


        # return list of deleted keys
        print('list of deleted api keys: ', deleted_keys_list)
        return {
            'statusCode': 200,
            'body': json.dumps("{}".format(str(deleted_keys_list))),
        }

    except ClientError as e:
        print(e)
        return {
            'statusCode': 500,
            'body': json.dumps("{}".format(str(e))),
        }
    except Exception as e:
        print(e)
        return {
            'statusCode': 500,
            'body': json.dumps("{}".format(str(e))),
        }

