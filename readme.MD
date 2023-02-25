# Project Title

Auth API

## Description

Backend authentication service that provides endpoints for user account management & token authorisation.


## Usage

This application should be run using docker. The following environment variables are required:

| Name      | Description |
| ----------- | ----------- |
| AWS_ACCESS_KEY      | Access key for an AWS user or role with access to Cognito     |
| AWS_SECRET_KEY | Secret access key for an AWS user or role with access to Cognito     |
| COGNITO_POOL_ID      | ID of the Cognito userpool    |
| AWS_REGION_NAME | Name of the region in AWS e.g "eu-west-1"     |
| APP_CLIENT_ID      | Client ID for the App client registered in AWS Cognito     |
| APP_CLIENT_SECRET | Client Secret for the App client registered in AWS Cognito     |


e.g sudo docker run -e AWS_ACCESS_KEY=123 -e AWS_SECRET_KEY=123 -e COGNITO_POOL_ID=123 -e AWS_REGION_NAME=eu-west-1 -e APP_CLIENT_ID=123 -e APP_CLIENT_SECRET=123 -d auth-api:latest



## Development

To set up the app in a development environment:

- Clone the repository
- Run 'make' to activate the virtual environment
- Run 'make run' to start local server
