# Project Title

This script spin up 2x AWS instances and deploy docker container with simple HTTP server written in python.

## Project Description

Below is what I was tasked with:

Here is a basic python http server that I wrote:
https://gist.github.com/skwp/d913829f43bc009a38956f79dc90c555

Please write a script that:

0. Builds a docker container from the python script and push it to Amazon ECR (container registry)
1. Spins up 2 servers in AWS (I recommend using us-east-1 region and ami-00129b193dc81bc31 which is the amazon linux ami that has docker already installed)
2. Deploys my server using docker
3. Loop and check that each server is running successfully on port 8080 (don't use AWS health checks, write this yourself)
4. Print a message that everything is healthy

Use of any language and any open source tools you like is allowed. Take shortcuts that will make this assignment easier. If you don't have an AWS account, create one and use the free t2.micro instances for this assignment.

Submit this assignment as a github repo. It should include at minimum a Dockerfile and a script to provision/health check the instances. Document everything in a README

## How it works

the script will:

0. Builds a docker container from the python script and push it to Amazon ECR (container registry)
    * use git to clone repository with the source code of simple HTTP server written in python https://gist.github.com/skwp/d913829f43bc009a38956f79dc90c555 to app_to_deploy/src directory
    * connect to AWS ECS and create ECR repository
    * build docker image out of simple python HTTP server located in app_to_deploy/src using Dockerfile located in app_to_deploy/Dockerfile
    * tag docker image we've just created for private repository - we use AWS ECR repo
    * get login token from ECR for docker to connect to this repository
    * getting docker logging in to repository
    * push image that was created in step 3 to repository

1. Spins up 2 servers in AWS
    * create ECS Cluster. This cluster is required for deploying docker containers later. When spinning up virtual machines we will place them into this cluster using user data field
    * detect our public IP (this is required to create security group, this IP will be the only allowed source IP for checking HTTP health status). To detect public IP I use ipify.org. they have simple API and service is very reliable. Public IP can also be specified manually.
    * create EC2 Security Group. This group will allow to perform HTTP health check on port 8080 after deploying HTTP server. This group also allow to SSH to our instances (port 22) and incoming ICMP traffic - which is technically not required, but was nice to have during development.
    * create EC2 Key Pair if pair does not exist. This is also not required, but nice to have in order to login to our EC2 instances
    * start 2 EC2 instances using Key Pair, Security Group and ECS Cluster that we've created
    * wait until all instances are running

2. Deploys simple HTTP server written in python using docker (I use AWS ECS)
    * Create ECS task definition that will deploy our docker image located in AWS ECR repo
    * Create ECS Service that will deploy 2 docker containers
    * wait till all docker containers are deployed

3. Loop and check that each server is running successfully on port 8080
    * determine Public IP of each AWS EC2 instance we started
    * perform health check of check instance. Here is how it works: Loop through instances during specific amount of time waiting for all instance to reply with HTTP status 200. If request times out or HTTP response status is 4XX client error or 5XX server error then instance is not alive. When all instances successfully replied with no HTTP error we stop looping. We also stop looping after predefined time timeout

4. Print a message that everything is healthy
    * if number of instances that passed HTTP health check equals to number of instances that we ran we print message that everything is healthy.

## Dockerfile

I created Dockerfile to deploy simple HTTP server written in python.

1. It looks like HTTP server is python 2 application because there is no parantheses after print statement (change in the print-syntax is well known change in python 3 vs python 2. Python 2’s print statement has been replaced by the print() function, meaning that we have to wrap the object that we want to print in parantheses.). In this Dockerfile I use python 2.7.
2. there is no dependency but I added dependency.txt file, so we can use pip to install required deps in the future.
3. I use minimalistic base image - Alpine, so my container takes about 100Mb comparing to traditional container python:2.7 that takes more than 700Mb.
4. Docker will create wwwroot directory in docker image. This directory will be working directory for our simple HTTP server. Script itself will be located one level up and will not be seen through HTTP. Only files located in wwwroot will be visible over HTTP.
5. Docker will create test.html file in wwwroot directory of our docker image. This file will be used for HTTP health check of our instances.

## Getting Started

This script is written in python 3.

Files and Directories:
deploy_python_server.py - this is the script to deploy HTTP server written in python
requirements.txt - list of required modules
app_to_deploy - directory with Dockerfile and http server that need to be deployed
app_to_deploy/requirements.txt - list of required modules for HTTP server (empty file)
app_to_deploy/Dockerfile - Dockerfile to build docker image from HTTP servers
app_to_deploy/src - directory with source code of HTTP server. This directory is now empty. The script will clone Simple HTTP server source code to this directory

Script utilized python standard logging. Logging level is set to INFO by default and it logs to stderr. You may want to set different logging level before running the script by setting up environment variable LOGLEVEL. For example:
export LOGLEVEL=DEBUG

### Prerequisites

I use python 3 and the following dependencies:
  * docker - Docker API
  * boto3 - AWS API
  * gitpython - to clone git

Before running the script you need to setup environment variable:
export AWS_ACCESS_KEY_ID=your_aws_access_key_id
export AWS_SECRET_ACCESS_KEY=your_aws_secret_key

### Installing

you can use pip to install all dependencies
pip3 install --no-cache-dir -r requirements.txt

## Authors

* **Konstantin Lebedev** - *Initial work* - [konsat](https://github.com/konsat)
