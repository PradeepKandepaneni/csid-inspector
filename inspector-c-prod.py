from docopt import docopt
import boto3
import sys
from datetime import datetime
from datetime import timedelta

SNS_TOPIC_ARN = 'arn:aws:sns:us-west-2:463796240916:InspectorJob'

def setupBotoSession(account_id=None, role_name=None):
    creds = {}
    if account_id and role_name:
        print "Using alternate external account, {0}, for deployment with role, {1}" .format(account_id, role_name)
        role_arn = "arn:aws:iam::" + account_id + ":role/"
        role_arn += role_name
        sts = boto3.client('sts')
        stsresponse = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=role_name)
        creds['aws_access_key_id'] = stsresponse['Credentials']['AccessKeyId']
        creds['aws_secret_access_key'] = stsresponse[
            'Credentials']['SecretAccessKey']
        creds['aws_session_token'] = stsresponse['Credentials']['SessionToken']
        print account_id
        print role_name
    else:
        pass
    botosession = boto3.session.Session(**creds)
    return botosession, creds


def tag_exists(TagsList=None, WantedTag=None):
    for tag in TagsList:
        if WantedTag in tag['Key']:
            return True
    return False


def tagValue(TagsList=None, WantedTag=None):
    for tag in TagsList:
        if WantedTag in tag['Key']:
            return tag['Value']
    return None


def getVulnPackageARN(inspectorClient=None):
    vulns_rp = 'Common Vulnerabilities and Exposures'
    rpARNS = []
    rpARNS = inspectorClient.list_rules_packages()['rulesPackageArns']
    for arn in rpARNS:
        response = inspectorClient.describe_rules_packages(
            rulesPackageArns=[
                arn,
            ],
            locale='EN_US'
        )
        if vulns_rp in response['rulesPackages'][0]['name']:
            return response['rulesPackages'][0]['arn']
    return None


def running_scans(templateARNS=None, inspectorClient=None):
    running = 0
    for tARN in templateARNS:
        response = inspectorClient.list_assessment_runs(
            assessmentTemplateArns=[
                tARN,
            ],
            filter={
                'states': [
                    'START_DATA_COLLECTION_PENDING', 'START_DATA_COLLECTION_IN_PROGRESS','COLLECTING_DATA','STOP_DATA_COLLECTION_PENDING','DATA_COLLECTED','EVALUATING_RULES',                      #Any status that covers an ongoing scan being processed.
                ]
            }
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            if response['assessmentRunArns']:
                running += 1                                                                                                                                                                       #At least one assessment run of these type of assessment template (service) is currently being processed.
                print('at least one assessment run is found being processed for assessment tempalte: {}\n'.format(tARN))
        else:
            print ('something went wrong when trying to grab the assessment runs running for this particular template: {} \n'.format(tARN))
    return running


def assessmentRun_thisWeek(templateARN=None, inspectorClient=None):
    '''
    :param templateARNS: assessment template ARN (single arn string)
    :param inspectorClient: connection to the inspector services in AWS account
    :return: True: if there was an assessment run completed this week. \ False: no assessment run has been completed this week.
    '''
    weekago = datetime.now() - timedelta(days=7)
    today   = datetime.today()
    rsp = inspectorClient.list_assessment_runs(
        assessmentTemplateArns=[
            templateARN,
        ],
        filter={
            'states': [
                'COMPLETED'
            ],
            'completionTimeRange': {
                'beginDate': weekago,
                'endDate': today
            },
        }
    )
    if rsp['assessmentRunArns']:
        return True
    else:
        return False


def assessmentRunningNow(templateARN=None, inspectorClient=None):
    running = False
    tARN    = templateARN
    response = inspectorClient.list_assessment_runs(
        assessmentTemplateArns=[
            tARN,
        ],
        filter={
            'states': [
                'START_DATA_COLLECTION_PENDING', 'START_DATA_COLLECTION_IN_PROGRESS','COLLECTING_DATA','STOP_DATA_COLLECTION_PENDING','DATA_COLLECTED','EVALUATING_RULES', #Any status that covers an ongoing scan being processed.
            ]
        }
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        if response['assessmentRunArns']:
            return True
            #print('at least one assessment run is found being processed for assessment tempalte: {}\n'.format(tARN))
        else:
            return False
    else:
        print('something went wrong when trying to grab the assessment runs running for this particular template: {} \n'.format(tARN))
        sys.exit(1)


def inspector_scheduler(templateARNS=None, inspectorClient=None):
    '''
    # run the assessment template with inspector.start_assessment_run
    response = client.start_assessment_run(
        assessmentTemplateArn='string',
        assessmentRunName='string'
    )
    '''
    assessments_running = 0
    #MAX_SRV_SCANS = 3               #Max number of services that can be scanning in at one time.
    iclient = inspectorClient
    '''
    0) - Make sure there are no more than 3 running scans.
    1) - Receives a list of assessment templates ARNS.
    2) - Grab the current number of scans running.
    3) - Go thru the list of templateARNs received and check:
            a) is the assessment template currently running for this target?
            --> NO: b) has the assessment template had any runs in the last week?
                    --> NO c) are there more than 3 assessment runs (for 3 different services) already running at this time?
                            --> NO: start assessment run for this template.
    '''
    RNOW = running_scans(templateARNS=templateARNS, inspectorClient=iclient)
    if RNOW >= 3:
        print("There are 3 different assessment templates are running, quiting now")
        sys.exit(0)
    for tARN in templateARNS:
        if not assessmentRun_thisWeek(templateARN=tARN,inspectorClient=iclient):                                  #move on only if the service has NOT been scanned within the last week.
            if not assessmentRunningNow(templateARN=tARN,inspectorClient=iclient):                                # Assessment is not running NOW for this target.
                if assessments_running <= 3:
                    print ("STARTING ASSESSMENT RUN FOR TARGET: {}\n".format(tARN))
                    try:
                        rsp = iclient.start_assessment_run(
                            assessmentTemplateArn=tARN,
                        )
                    except Exception as e:
                        print("ERROR STARTING SCAN for ASSESSMENT TEMPLATE: {}".format(tARN))
                        print(e.message)
                    else:
                        if rsp['ResponseMetadata']['HTTPStatusCode'] == 200:
                            assessments_running += 1
                else:
                    print ("3 Assessments already running. exiting now\n\n\n")
                    sys.exit(0)

            else:
                print ("Assessment run is currently running for this template: {} \n".format(tARN))
        else:
            print ("Assessment run already completed within the last 7 days for target: {}\n".format(tARN))


def main():
    account_number = '463796240916'
    assumerole='Jenkins-Production'
    session, awscreds = setupBotoSession(account_id=account_number, role_name=assumerole)
    ec2 = session.client('ec2',region_name='us-west-2')
    ec2_resource = session.resource('ec2',region_name='us-west-2')
    inspected_services    = []
    notinspected_services = []
    checked_services      = {}
    ec2s = ec2.describe_instances(Filters=[{'Name':'instance-state-name','Values':['running']}])
    for reservation in ec2s['Reservations']:
        instances = reservation['Instances']
        for ec2instance in instances:
            print("Ec2 Instance", ec2instance)
            inst_tags = ec2.describe_tags(Filters=[{'Name': 'resource-id', 'Values': [ec2instance['InstanceId']]}])['Tags']
            srv = {}
            srvname = ''
            isinspected = False
            srvname = tagValue(TagsList=inst_tags, WantedTag='Service')
            print("Service",srvname)
            if srvname not in checked_services:
                checked_services[srvname] = 'checked'
                print("checked services",checked_services)
                inspectorvalue = tagValue(TagsList=inst_tags, WantedTag='AWSInspector')
                print("InspectorValue",inspectorvalue)
                if inspectorvalue == 'true':
                    srv.update({'serviceName':srvname})
                    srv.update({'AWSInspector':'True'})
                    inspected_services.append(srv)
                    print("************Inspected",inspected_services)
                    print(srv)
                else:
                    srv.update({'serviceName': srvname})
                    srv.update({'AWSInspector': 'False'})
                    notinspected_services.append(srv)
                    print("Not inspected-----------",notinspected_services)

    inspector = session.client('inspector', region_name='us-west-2')
    vulns_rp_arn = getVulnPackageARN(inspectorClient=inspector)                     #Function to get the ARN of the rules package for Common Vulns and Exposures. (different for each account)
    if vulns_rp_arn == None:
        print ("Error trying to get the ARN of the Rule Package for Vulnerabilities and Exposures. - Exiting now.\n")
        sys.exit(1)
    #ASSESSMENT_TARGETS = []
    ASSESSMENT_TEMPLATES = []
    #srv_inspector = {}
    for iserv in inspected_services:
        srv_inspector = {}
        srv_inspector.update({'serviceName':iserv['serviceName']})
        #Check if there are any assessment targets created for this service:
        pattern = iserv['serviceName'] + '*'
        if iserv['serviceName'] == 'offers':
            pattern = 'offers'                                                                                                          #workaround for the offerts/offersfoundry service.
        targets = inspector.list_assessment_targets(filter = {'assessmentTargetNamePattern': pattern},maxResults = 123)                 #look for the assessment targets for this service
        if not targets['assessmentTargetArns']: #EMPTY list of assessment target arns.                                                  #none found.
            #there is no assessment target for this service. creating one now.
            print ("No Assessment targets found for this microservice: {}\n".format(iserv['serviceName']))
            print("Creating NEW resource group for this microservice {}\n".format(iserv['serviceName']))
            resource_group = inspector.create_resource_group(resourceGroupTags=[                                                         # No need to know about the AWSInspector tag, it's already part of inspected_services.
                    {
                        'key': 'Service',
                        'value': iserv['serviceName']
                    },
                ]
            )
            if not resource_group:
                print("Error creating resource group for this microservice: {}\n".format(iserv['serviceName']))
                sys.exit(1)
            else:
                resource_groupARN = resource_group['resourceGroupArn']
                print("Resource Groups created successfully - now creating assessment target\n")
                print("Creating NEW Assessment Target for microservice {}\n".format(iserv['serviceName']))
                '''
                limitation: You can create up to 50 assessment targets per AWS account. source: http://boto3.readthedocs.io/en/latest/reference/services/inspector.html#Inspector.Client.create_assessment_target
                '''
                assessment_target = inspector.create_assessment_target(          #CREATING ASSESSMENT TARGET
                    assessmentTargetName=iserv['serviceName'],
                    resourceGroupArn=resource_groupARN
                )
                if assessment_target['assessmentTargetArn']:
                    print ("Assessment Target created successfully for micro-service: {}".format(iserv['serviceName']))
                    srv_inspector.update({'assessmentTargetArn':assessment_target['assessmentTargetArn']})
                else:
                    print ("Error creating the assessment target for this microservice: {}".format(iserv['serviceName']))
                    sys.exit(1)

            #continue here with the assessment templates creation: #NOTE: this codes repeats down below. may need to put a function in place.
            #######################################################################################################################################
            targetARN = assessment_target['assessmentTargetArn']
            # Now check the assessment templates for this service:
            templates = inspector.list_assessment_templates(
                assessmentTargetArns=[targetARN])  # query assessment templates for targets received.
            if not templates['assessmentTemplateArns']:  # None found.
                # create the assessment templates.
                print('something went ugly, there are not any assessment templates for this microservice: {}\n'.format(
                    iserv['serviceName']))
                print('Creating assessment template for this microservice: {}\n'.format(iserv['serviceName']))
                newtemplate = inspector.create_assessment_template(
                    assessmentTargetArn=targetARN,
                    assessmentTemplateName='IVulnScan-' + iserv['serviceName'],
                    durationInSeconds=3600,  #ONE HOUR IN DURATION FOR VULNERABILITY SCANS.
                    rulesPackageArns=[
                        vulns_rp_arn,
                    ]
                )
                if newtemplate['ResponseMetadata']['HTTPStatusCode'] == 200:
                    print (
                    "New Assessment Template Created Successfuly for MicroService: {}\n".format(iserv['serviceName']))
                    print ("Subscribing template to the correct topic so logs go to splunk\n")
                    resp = inspector.subscribe_to_event(
                        resourceArn=newtemplate['assessmentTemplateArn'],
                        event='FINDING_REPORTED',
                        topicArn=SNS_TOPIC_ARN  # NOTE:need to add this to docopt
                    )
                    if resp['ResponseMetadata']['HTTPStatusCode'] == 200:  #ASSESSMENT TEMPLATE SUBSCRIBED TO TOPIC.
                        print(
                        "Assessment template subscribed correctly to ECS-SEC-STACK SNS Topic for sending logs to splunk\n")
                        print(
                        "Appending assessment template ARN to ARNs list to pass it along to the inspector scheduler.\n")
                        ASSESSMENT_TEMPLATES.append(newtemplate['assessmentTemplateArn'])
                        # run assessment run with inspector.start_assessment_run
                    else:
                        print("Error with SNS topic subscription for assessment template: {}".format(
                            str(newtemplate['assessmentTemplateArn'])))
                        sys.exit(1)
            else:
                if len(templates['assessmentTemplateArns']) > 1:
                    print(
                    'something went wrong, there are more than 1 asessment templates for this microservice: {}\n'.format(
                        iserv['serviceName']))
                    sys.exit(1)
                else:
                    templateARN = templates['assessmentTemplateArns'][0]
                    ASSESSMENT_TEMPLATES.append(templateARN)
###################################################################################################################################################
        else:                                                                                                                                      #  FOUND ASSESSMENT TARGETS CHECKING FOR ASSESSMENT TEMPLATES.
            print ("got the assessment targets for this microservice {}\n").format(iserv['serviceName'])
            if len(targets['assessmentTargetArns']) > 1:
                print('something went sideways, there should only be 1 Assessment target ARN for each microservice, service name: {}\n'.format(iserv['serviceName']))
                sys.exit(1)
            else:
                targetARN = targets['assessmentTargetArns'][0]
                # Now check the assessment templates for this service:
                templates = inspector.list_assessment_templates(assessmentTargetArns=[targetARN])                                                    # QUERY ASSESSMENT TEMPLATES FOR THE TARGETS THAT I GOT.
                if not templates['assessmentTemplateArns']:                                                                                          # None found.
                    #create the assessment templates.
                    print('something went ugly, there are not any assessment templates for this microservice: {}\n'.format(iserv['serviceName']))
                    print('Creating assessment template for this microservice: {}\n'.format(iserv['serviceName']))
                    newtemplate = inspector.create_assessment_template(
                        assessmentTargetArn=targetARN,
                        assessmentTemplateName='IVulnScan-'+iserv['serviceName'],
                        durationInSeconds=3600,                                                                                                      #ONE HOUR IN DURATION FOR VULNERABILITY SCANS.
                        rulesPackageArns=[
                            vulns_rp_arn,
                        ]
                    )
                    if newtemplate['ResponseMetadata']['HTTPStatusCode'] == 200:
                        print ("New Assessment Template Created Successfuly for MicroService: {}\n".format(iserv['serviceName']))
                        print ("Subscribing template to the correct topic so logs go to splunk\n")
                        resp = inspector.subscribe_to_event(
                            resourceArn=newtemplate['assessmentTemplateArn'],
                            event='FINDING_REPORTED',
                            topicArn=SNS_TOPIC_ARN                                                                                                          #NOTE: Need to add docopt here.
                        )
                        if resp['ResponseMetadata']['HTTPStatusCode'] == 200:                                                                               #ASSESSMENT TEMPLATE SUBSCRIBED TO TOPIC.
                            print("Assessment template subscribed correctly to ECS-SEC-STACK SNS Topic for sending logs to splunk\n")
                            print("Appending assessment template ARN to ARNs list to pass it along to the inspector scheduler.\n")
                            ASSESSMENT_TEMPLATES.append(newtemplate['assessmentTemplateArn'])
                            #run assessment run with inspector.start_assessment_run
                        else:
                            print("Error with SNS topic subscription for assessment template: {}".format(str(newtemplate['assessmentTemplateArn'])))
                            sys.exit(1)
                else:
                    if len(templates['assessmentTemplateArns']) > 1:
                        print('something went wrong, there are more than 1 asessment templates for this microservice: {}\n'.format(iserv['serviceName']))
                        sys.exit(1)
                    else:
                        templateARN = templates['assessmentTemplateArns'][0]
                        ASSESSMENT_TEMPLATES.append(templateARN)
    print("Passing   {}   ASSESSMENT TEMPLATES to the inspector scheduler.\n".format(len(ASSESSMENT_TEMPLATES)))
    inspector_scheduler(templateARNS=ASSESSMENT_TEMPLATES, inspectorClient=inspector)

if __name__ == '__main__':
    main()
