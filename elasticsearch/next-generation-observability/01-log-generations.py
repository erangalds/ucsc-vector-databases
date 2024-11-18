import openai
import ast
import json
from elasticsearch import Elasticsearch, helpers
from sklearn.feature_extraction.text import TfidfVectorizer
from faker import Faker
import random

fake = Faker()

# 1. Apache HTTP Server (Common Log Format)
def generate_apache_log():
    return '{RemoteHost} - - [{Timestamp}] "{RequestMethod} {RequestURI} {Protocol}" {StatusCode} {ResponseSize}'.format(
        RemoteHost=fake.ipv4(),
        Timestamp=fake.date_time_this_year().strftime('%d/%b/%Y:%H:%M:%S %z'),
        RequestMethod=fake.http_method(),
        RequestURI=fake.uri(),
        Protocol='HTTP/1.1',
        StatusCode=random.choice([200, 404, 500]),
        ResponseSize=random.randint(100, 10000)
    )

# 2. Nginx (Combined Log Format)
def generate_nginx_log():
    return '{RemoteAddress} - {RemoteUser} [{Timestamp}] "{RequestMethod} {RequestURI} {Protocol}" {StatusCode} {ResponseSize} "{Referer}" "{UserAgent}"'.format(
        RemoteAddress=fake.ipv4(),
        RemoteUser='-',
        Timestamp=fake.date_time_this_year().strftime('%d/%b/%Y:%H:%M:%S %z'),
        RequestMethod=fake.http_method(),
        RequestURI=fake.uri(),
        Protocol='HTTP/1.1',
        StatusCode=random.choice([200, 404, 500]),
        ResponseSize=random.randint(100, 10000),
        Referer=fake.uri(),
        UserAgent=fake.user_agent()
    )

# 3. Syslog (RFC 5424)
def generate_syslog():
    return '<{Priority}>{Version} {Timestamp} {Hostname} {AppName} {ProcID} {MsgID} {StructuredData} {Message}'.format(
        Priority=random.randint(1, 191),
        Version=1,
        Timestamp=fake.date_time_this_year().isoformat(),
        Hostname=fake.hostname(),
        AppName=fake.word(),
        ProcID=random.randint(1000, 9999),
        MsgID=random.randint(1000, 9999),
        StructuredData='-',
        Message=fake.sentence()
    )

# 4. AWS CloudTrail
def generate_aws_cloudtrail_log():
    return '{{"eventVersion": "{EventVersion}", "userIdentity": {{"type": "IAMUser", "userName": "{UserName}"}}, "eventTime": "{Timestamp}", "eventSource": "{EventSource}", "eventName": "{EventName}", "awsRegion": "{AwsRegion}", "sourceIPAddress": "{SourceIPAddress}", "userAgent": "{UserAgent}", "requestParameters": {{"key": "value"}}, "responseElements": {{"key": "value"}}, "requestID": "{RequestId}", "eventID": "{EventId}", "eventType": "AwsApiCall", "recipientAccountId": "{RecipientAccountId}"}}'.format(
        EventVersion='1.08',
        UserName=fake.user_name(),
        Timestamp=fake.date_time_this_year().isoformat(),
        EventSource='s3.amazonaws.com',
        EventName='GetObject',
        AwsRegion='us-east-1',
        SourceIPAddress=fake.ipv4(),
        UserAgent=fake.user_agent(),
        RequestId=fake.uuid4(),
        EventId=fake.uuid4(),
        RecipientAccountId=fake.random_number(digits=12)
    )

# 5. Microsoft Windows Event Log
def generate_windows_event_log():
    return '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{ProviderName}"/><EventID>{EventID}</EventID><Level>{Level}</Level><TimeCreated SystemTime="{Timestamp}"/><SourceName>{SourceName}</SourceName><Computer>{Computer}</Computer></System><EventData>{Message}</EventData></Event>'.format(
        ProviderName=fake.word(),
        EventID=random.randint(1000, 9999),
        Level=random.randint(1, 5),
        Timestamp=fake.date_time_this_year().isoformat(),
        SourceName=fake.word(),
        Computer=fake.hostname(),
        Message=fake.sentence()
    )

# 6. Linux Audit Log
def generate_linux_audit_log():
    return 'type={AuditType} msg=audit({Timestamp}): {Message}'.format(
        AuditType=fake.word(),
        Timestamp=fake.date_time_this_year().isoformat(),
        Message=fake.sentence()
    )

def generate_logs(sources, total_logs, random_logs):
    # Mapping source names to their corresponding log generation functions
    source_to_function = {
        'apache': generate_apache_log,
        'nginx': generate_nginx_log,
        'syslog': generate_syslog,
        'aws_cloudtrail': generate_aws_cloudtrail_log,
        'windows_event': generate_windows_event_log,
        'linux_audit': generate_linux_audit_log,
    }
    
    # Calculate the number of logs to generate for each source
    num_sources = len(sources)
    logs_per_source = [total_logs // num_sources] * num_sources
    if random_logs:
        for i in range(total_logs % num_sources):
            logs_per_source[i] += 1
        random.shuffle(logs_per_source)
    
    # Generate the logs and append them to the list
    generated_logs = []
    for source, num_logs in zip(sources, logs_per_source):
        log_function = source_to_function[source]
        for _ in range(num_logs):
            generated_logs.append(log_function())
    
    return generated_logs

