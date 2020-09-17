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


def data_table(df, column):
    result_table = '<table border = 1><tr bgcolor="Blue"><th>Resource Type</th><th>Resource Name / Id</th><th>{}</th></tr>'
    result_table = result_table.format(column)
    # print(column)
    # print(result_table)
    for index, row in df.iterrows():
        result_table += '<tr><td>{}</td><td>{}</td><td>{}</td>'.format(
            row['resourceType'], row['resourceName'], row['reason'])
    result_table += '</table>'
    return result_table


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
