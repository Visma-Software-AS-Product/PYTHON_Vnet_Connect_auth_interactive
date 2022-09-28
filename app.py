from flask import Flask, url_for, redirect, render_template, session, request

import base64
import hashlib
import os
import re
import logging
import requests
import json

logging.basicConfig(filename='log.log', filemode='w', level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

authorize_url = 'https://connect.visma.com/connect/authorize'
token_url = 'https://connect.visma.com/connect/token'

# code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
# code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

# code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
# code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
# code_challenge = code_challenge.replace("=", "")

@app.route('/')
def index():
    return render_template('index.html')
   
@app.route('/login')
def login():

    state = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")

    auth_request = authorize_url
    auth_request += "?response_type=code"
    auth_request += "&client_id=" + os.environ.get('CLIENT_ID')
    auth_request += "&redirect_uri=" + url_for('authorize', _external=True) 
    auth_request += "&scope=vismanet_erp_interactive_api:create vismanet_erp_interactive_api:delete vismanet_erp_interactive_api:read vismanet_erp_interactive_api:update"
    auth_request += "&state=" + state
    # auth_request += "&code_challenge=" + code_challenge
    # auth_request += "&code_challenge_method=S256"

    session['state'] = state

    return redirect(auth_request)          

@app.route('/authorize')    
def authorize():
    
    code = request.args['code']
    state = request.args['state']

    if state == session['state']:
    
        reqdata = "grant_type=authorization_code" 
        reqdata += "&code=" + code
        reqdata += "&client_id=" + os.environ.get('CLIENT_ID')
        reqdata += "&client_secret=" + os.environ.get('CLIENT_SECRET')
        reqdata += "&redirect_uri=" + url_for('authorize', _external=True) 
        # reqdata += "&code_verifier=" + code_verifier        
        
        response = requests.post(token_url,
                                data=reqdata,
                                headers={'Content-Type': 'application/x-www-form-urlencoded'}
                                )

        if response.status_code == 200:
            json_data = json.loads(response.text)
            session["access_token"] = json_data["access_token"]

    return redirect("/inventory")

@app.route('/inventory')
def inventory():

    response = requests.get("https://integration.visma.net/API/controller/api/v1/inventory/?pageSize=10",                          
                            headers={
                                'Accept': 'application/json',
                                'Authorization': 'Bearer ' + session['access_token']                                
                            }
                        )

    if response.status_code == 200:
        result = json.loads(response.text)
        