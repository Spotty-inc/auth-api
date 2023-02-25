import os
import logging
import boto3
from flask import Flask, jsonify, request
from dotenv import load_dotenv
from Models.cognito import CognitoIdentityProviderWrapper

load_dotenv()

app = Flask(__name__)

logger = logging.getLogger(__name__)

client = boto3.client('cognito-idp', region_name=os.getenv('AWS_REGION_NAME'), aws_access_key_id=os.getenv('AWS_ACCESS_KEY'),
                        aws_secret_access_key=os.getenv('AWS_SECRET_KEY'))
c = CognitoIdentityProviderWrapper(cognito_idp_client=client, user_pool_id=os.getenv('COGNITO_POOL_ID'),
                                    client_id=os.getenv('APP_CLIENT_ID'), client_secret=os.getenv('APP_CLIENT_SECRET'))

@app.route('/users', methods=['GET'])
def list_users():
    users = c.list_users()
    return jsonify(users)


@app.route('/user/<username>')
def get_user(username):
    user = c.get_user(username)
    return jsonify(user)


@app.route('/register', methods=['POST'])
def create_user():
    username = request.args['username']
    password = request.args['password']
    user_email = request.args['user_email']
    confirmed = c.sign_up_user(username=username, password=password,
                   user_email=user_email)
    return jsonify(confirmed)


@app.route('/confirm', methods=['POST'])
def confirm_user():
    username = request.args['username']
    confirmation_code = request.args['confirmation_code']
    d = c.confirm_user(username= username,confirmation_code=confirmation_code)
    if d:
        return jsonify("Success: User confirmed")
    else:
        return jsonify("Error confirming user")


@app.route('/confirm/resend', methods=['POST'])
def resend_confirmation_email():
    username = request.args['username']
    delivery = c.resend_confirmation(username=username)
    return jsonify(delivery)


@app.route('/login', methods=['POST'])
def sign_in_user():
    username = request.args['username']
    password = request.args['password']
    response = c.start_sign_in(username=username,password=password)
    return jsonify(response)

if __name__ == '__main__':
    app.run()
