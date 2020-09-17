import json
import boto3
import os
#from datetime import date, timedelta
import datetime
from _datetime import timedelta
from botocore.exceptions import ClientError
import re
from awsunusedresources import unused_res
import sys


def main():
    print('Finding Unused Resources in AWS:')
    try:
        unused_res(os.environ['days'], os.environ['sender'],
                   os.environ['receiver'], os.environ['app'], os.environ['env'])
    except:
        print("error in execution")

    return {
        'statusCode': 200,
        'body': json.dumps("success")
    }


if __name__ == '__main__':
    sys.exit(main())
