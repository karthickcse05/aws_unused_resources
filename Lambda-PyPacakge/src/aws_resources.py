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
from awsunusedresources import unused_res


def lambda_handler(event, context):
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
