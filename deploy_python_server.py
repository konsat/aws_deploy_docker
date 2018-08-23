#!/usr/local/bin/python3

# set up AWS credentials before running this script:
#
# export AWS_ACCESS_KEY_ID=youraccesskey
# export AWS_SECRET_ACCESS_KEY=yoursecretaccesskey
#
# you can set logging level before running this script
# export LOGLEVEL=DEBUG

APP_GIT = 'https://gist.github.com/d913829f43bc009a38956f79dc90c555.git'    # git path to clone our simple HTTP server written in Python
DOCKERFILE_PATH = './app_to_deploy'                                         # path to Dockerfile that will create docker image out of our simple HTTP server

AWS_REGION = 'us-east-1'                            # AWS region
ECR_REPO = 'test_ecr_repository'                    # name of ECR repository we will create
DOCKER_IMAGE = 'mysimplehttpserver_image'           # name(tag) of docker image we put into ECR repo

ECS_CLUSTER_NAME = 'My_ECS_Cluster'                 # name of ECS Cluster we create to deploy docker containers
ECS_TASK_DEFINITION_NAME = 'My_ECS_Task'            # name of ECS Task Definition that will deploy docker containers
ECS_SERVICE_NAME = 'My_ECS_Service'                 # name of ECS Service that will deploy docker containers

SECURITY_GROUP_NAME = 'SecGr_allow_SSH_and_8080'    # name of EC2 Security Group that we create
KEYPAIR_NAME = 'KP_myhttpserver'                    # name of EC2 Key Pair that we create
EC2_INSTANCE_TYPE = 't2.micro'                      # instance type that we spin up
INSTANCE_COUNT = 2

TEST_ECS_INTERVAL = 10                              # how often we check that ECS tasks are up
TEST_ECS_DURATION = 150                             # how long do we wait for ECS tasks to come up

TEST_HTTP_PATH = '/test.html'                       # path to use in HTTP health check
TEST_HTTP_TIMEOUT = 1                               # HTTP request time out. during HTTP health check our HTTP server should reply fater then this timeout
TEST_HTTP_INTERVAL = 10                             # how often we perform HTTP health check of each instance
TEST_HTTP_DURATION = 150                            # how long do we perform HTTP health check

myPublicIP = ''

import logging.config
import os, base64, requests, docker, boto3
from botocore.exceptions import ClientError, ParamValidationError
from time import sleep
from collections import defaultdict
from git import Repo

def main():
    log.info('Started')

    # verify credentials are set
    if not (os.environ.get('AWS_ACCESS_KEY_ID', '') and os.environ.get('AWS_SECRET_ACCESS_KEY', '')):
        print("""
                 set up AWS credentials before running this script:
                 export AWS_ACCESS_KEY_ID=youraccesskey
                 export AWS_SECRET_ACCESS_KEY=yoursecretaccesskey""")
        log.info('AWS credentials not set. Exiting.')
        exit(1)

    # clone our python http server to src directory
    log.info('Cloning repo with our python http server src code')
    Repo.clone_from(APP_GIT, os.path.join(DOCKERFILE_PATH, 'src'))

    # 0
    log.info('task #0: Builds a docker container from the python script and push it to Amazon ECR (container registry)')

    # connect to AWS Docker registry service (ECR)
    ecr_client = boto3.client('ecr', region_name=AWS_REGION)

    # create a new repository. If it already exists get repository URL
    log.info('Creating new ECR repository')
    try:
        response = ecr_client.create_repository(repositoryName=ECR_REPO)
        repoURL = response['repository']['repositoryUri']
    except ecr_client.exceptions.RepositoryAlreadyExistsException:
        log.info('ECR Repository ' + ECR_REPO + ' already exists')
        response = ecr_client.describe_repositories(repositoryNames=[ECR_REPO])
        repoURL = response['repositories'][0]['repositoryUri']
    except ClientError as e:
        log.error(e)
        log.info('ECR client error. Exiting.')
        exit(2)
    log.debug('repository URL: ' + repoURL)

    # create an instance of a docker client
    docker_client = docker.from_env()

    # build docker image from Dockerfile
    log.info('Building docker image')
    (docker_image, buildlog) = docker_client.images.build(path=DOCKERFILE_PATH, tag=DOCKER_IMAGE)

    #docker_container = docker_client.containers.create(DOCKER_IMAGE, '-p 8080:8080')

    # tag docker image for a private repository (in our case ECR repository)
    log.info('Tagging docker image for ECR repo')
    docker_image.tag(repoURL, tag=DOCKER_IMAGE)

    # get login information
    log.info('Getting login info from ECR for docker login')
    token = ecr_client.get_authorization_token()
    username, password = base64.b64decode(token['authorizationData'][0]['authorizationToken']).decode().split(':')
    registry = token['authorizationData'][0]['proxyEndpoint']

    # login to repository
    log.info('Getting docker logged in to ECR repo')
    docker_client.login(username, password, registry=registry)

    # push image
    log.info('Pushing docker image to ECR repo')
    docker_client.images.push(repoURL, tag=DOCKER_IMAGE)

    log.info('task #0: Completed')
    # 1.
    log.info('task #1: Spins up 2 servers in AWS (I recommend using us-east-1 region and ami-00129b193dc81bc31 which is the amazon linux ami that has docker already installed)')

    # create an ECS instance
    ecs_client = boto3.client('ecs', region_name=AWS_REGION)

    # create an ECS cluster
    log.info('Creating ECS Cluster')
    response = ecs_client.create_cluster(clusterName=ECS_CLUSTER_NAME)

    # if our public IP is not set obtain it from external service ipify.org
    global myPublicIP
    if not myPublicIP:
        myPublicIP = requests.get('https://api.ipify.org').text
        log.debug('My public IP is %s', myPublicIP)

    # create a security group if not exists
    ec2 = boto3.resource('ec2', region_name=AWS_REGION)
    log.info('Creating Security Group')
    try:
        sec_group = ec2.create_security_group(
            GroupName = SECURITY_GROUP_NAME, Description = SECURITY_GROUP_NAME)
        log.info('Adding ingress rule to Security Group for ICMP traffic')
        sec_group.authorize_ingress(
            CidrIp = myPublicIP + '/32',
            IpProtocol = 'icmp',
            FromPort = -1,
            ToPort = -1)
        log.info('Adding ingress rule to Security Group for TCP:8080')
        sec_group.authorize_ingress(
            CidrIp = myPublicIP + '/32',
            IpProtocol = 'tcp',
            FromPort = 8080,
            ToPort = 8080)
        log.info('Adding ingress rule to Security Group for SSH (TCP:22)')
        sec_group.authorize_ingress(
            CidrIp = myPublicIP + '/32',
            IpProtocol = 'tcp',
            FromPort = 22,
            ToPort = 22)
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
            log.warning('Security group already exists. Make sure inbound rules are set!')
        else:
            log.error("Unexpected error: %s" % e)
            log.info('Could not create Security Group. Exiting.')
            exit(2)

    # create a keypair if not exists
    log.info('Creating Key Pair')
    try:
        key_pair_info = ec2.create_key_pair(KeyName = KEYPAIR_NAME)
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
            log.warning('Key Pair already exists')
        else:
            log.error("Unexpected error: %s" % e)
            log.info('Could not create Key Pair. Exiting.')
            exit(2)

    # create EC2 instances
    log.info('Creating EC2 instances')
    instance = ec2.create_instances(
        ImageId = 'ami-00129b193dc81bc31',
        MinCount = INSTANCE_COUNT,
        MaxCount = INSTANCE_COUNT,
        KeyName = KEYPAIR_NAME,
        SecurityGroups = [SECURITY_GROUP_NAME],
        InstanceType = EC2_INSTANCE_TYPE,
        IamInstanceProfile = {"Name": "ecsInstanceRole"},
        # By default, new instances launche into "default" cluster.
        # I use user data field to add cluster name into etc/ecs/ecs.config.
        UserData = "#!/bin/bash \n echo ECS_CLUSTER=" + ECS_CLUSTER_NAME + " >> /etc/ecs/ecs.config")
    log.debug('EC2 response: %s', instance)

    # waiting until instances are running
    instance_id = []
    for x in range(INSTANCE_COUNT):
        log.info('Waiting until instance #%d is running', x+1)
        instance[x].wait_until_running()
        instance_id.append(instance[x].id)
        log.info('Instance #%d id: %s is now running', x+1, instance_id[x])

    log.info('task #1: Completed')



    # 2.
    log.info('task #2: Deploys my server using docker')
    # I'm going to use ECS service to deploy Docker container application

    # Create ECS task definition
    log.info('Creating ECS task definition')
    response = ecs_client.register_task_definition(
        containerDefinitions=[
        {
          "name": ECS_TASK_DEFINITION_NAME,
          "image": repoURL + ':' + DOCKER_IMAGE,
          "essential": True,
          "portMappings": [
            {
              "hostPort": 8080,
              "protocol": 'tcp',
              "containerPort": 8080
            }
          ],
          "memory": 300,
          "cpu": 100
        }
        ],
        family = ECS_TASK_DEFINITION_NAME
    )
    #log.debug(response)

    # Create ECS Service
    log.info('Creating ECS Service')
    try:
        response = ecs_client.create_service(
            cluster = ECS_CLUSTER_NAME,
            taskDefinition = ECS_TASK_DEFINITION_NAME,
            serviceName = ECS_SERVICE_NAME,
            desiredCount = INSTANCE_COUNT,
            clientToken = 'request_identifier_string',
            deploymentConfiguration = {
                'maximumPercent': 100,
                'minimumHealthyPercent': 50
            }
        )
    except Exception as e:
        log.error(e)
        # TODO: if service already exist this script will not continue
        # TODO: Should I at least stop existing instances here?
        log.info('Could not create ECS Service. Exiting.')
        exit(2)

    log.info('Waiting for ECS service to run %d tasks. It may take up to %d sec', INSTANCE_COUNT, TEST_ECS_DURATION)
    serviceCount = 0
    for x in range(TEST_ECS_DURATION // TEST_ECS_INTERVAL):
        log.debug('service check #%d',  x)
        response = ecs_client.describe_services(
            cluster=ECS_CLUSTER_NAME,
            services=[ECS_SERVICE_NAME]
        )
        serviceCount = int(response['services'][0]['runningCount'])
        log.debug('number of running ECS tasks: %d', serviceCount)
        if serviceCount >= INSTANCE_COUNT:
            log.info('Number of running ECS tasks is now %d', serviceCount)
            break
        log.debug('waiting %d second(s)', TEST_ECS_INTERVAL)
        sleep(TEST_ECS_INTERVAL)
    if serviceCount < INSTANCE_COUNT:
        log.error('ECS service could not start %d ECS tasks in %d seconds', INSTANCE_COUNT, TEST_ECS_DURATION)
        # TODO: I should probably stop existing instances here and remove ECS service
        log.info('Could not start desired number of ECS tasks (docker containers). Exiting.')
        exit(2)

    log.info('task #2: Completed')



    # 3.
    log.info('task #3: Loop and check that each server is running successfully on port 8080 (don''t use AWS health checks, write this yourself)')

    # determine public IP of each instances
    running_instances = ec2.instances.filter(Filters=[
        {'Name': 'instance-state-name', 'Values': ['running']},
        {'Name': 'instance-id', 'Values': instance_id}
        ])
    public_ip_address = defaultdict(str)
    for i1, instance in enumerate(running_instances):
        public_ip_address[instance.id] = instance.public_ip_address
    for i2, id in enumerate(instance_id):
        log.info('instance #%d. id: %s, Public IP: %s', i2, id, public_ip_address[id])
    if i1+1 < INSTANCE_COUNT:
        log.error('Only %d running EC2 instance(s) detected. Expected: %d', i1+1, INSTANCE_COUNT)
        log.info('Number of instance invalid. Exiting.')
        exit(2)

    # perform HTTP health check
    log.info('Starting HTTP health check. It may take up to %d sec', TEST_HTTP_DURATION)
    for x in range(TEST_HTTP_DURATION // TEST_HTTP_INTERVAL):
        alive_instance_count = 0
        for index, id in enumerate(instance_id):
            try:
                response = requests.head('http://%s:8080%s' % (public_ip_address[id], TEST_HTTP_PATH), timeout=TEST_HTTP_TIMEOUT) # it raises exception if timeout or other issue
                response.raise_for_status() # it raises exception if there is a 4XX client error or 5XX server error response
                log.debug('instance #%d. id: %s, Public IP: %s - HTTP test passed, response status code %d', index, id, public_ip_address[id], response.status_code)
                alive_instance_count = alive_instance_count + 1
            except requests.exceptions.RequestException as e:
                log.debug('instance #%d. id: %s, Public IP: %s - HTTP exception: %s', index, id, public_ip_address[id], e)
        if alive_instance_count == INSTANCE_COUNT:
            log.info('all instances have passed HTTP health check')
            break
        log.debug('waiting %d second(s)', TEST_HTTP_INTERVAL)
        sleep(TEST_HTTP_INTERVAL)

    log.info('task #3: Completed')



    # 4.
    log.info('task #4: Print a message that everything is healthy')
    if alive_instance_count == INSTANCE_COUNT:
        print('all instances have passed HTTP health check')
    else:
        log.error('HTTP health check failed')

    log.info('task #4: Completed')
    log.info('Finished')





if __name__ == '__main__':
    # setup logger
    LOGFORMAT = '%(asctime)-15s %(levelname)-8s %(name)-10s %(message)s'
    log = logging.getLogger(__name__)
    logging.basicConfig(level=os.environ.get('LOGLEVEL', 'DEBUG'), format=LOGFORMAT)
#    logging.getLogger("boto3").setLevel(logging.ERROR)      # log only errors from boto3
#    logging.getLogger("botocore").setLevel(logging.ERROR)   # log only errors from botocore
#    logging.getLogger("docker").setLevel(logging.ERROR)     # log only errors from docker
#    logging.getLogger("urllib3").setLevel(logging.ERROR)    # log only errors from urllib3
#    logging.getLogger("git").setLevel(logging.ERROR)    # log only errors from urllib3
    log.debug('logger is configured')
    main()
