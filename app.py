from requests_oauthlib import OAuth2Session
from flask import Flask, url_for, redirect, render_template, session, request

import base64
import hashlib
import os
import re
import logging

logging.basicConfig(filename='log.log', filemode='w', level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'VerySecretKey'

client_id = 'vsas_vismanet_connect_interactive'
client_secret = 'j6y8ZmZMXzUqLZT5x2UNoZrk8sLlC09LQF76OOatt0MHyKhnIxlSq6weTwlYMO4a'
authorize_url = 'https://connect.visma.com/connect/authorize'
token_url = 'https://connect.visma.com/connect/token'

code_verifier = base64.urlsafe_b64encode(os.urandom(30)).decode("utf-8")
code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
code_challenge = code_challenge.replace("=", "")

# oauth = OAuth(app)
# oauth.register(
#     name='vismaconnect',
#     client_id='vsas_vismanet_connect_interactive',
#     client_secret='j6y8ZmZMXzUqLZT5x2UNoZrk8sLlC09LQF76OOatt0MHyKhnIxlSq6weTwlYMO4a',
#     access_token_url='https://connect.visma.com/connect/token',
#     access_token_params=None,
#     authorize_url='https://connect.visma.com/connect/authorize',
#     authorize_params={
#         'scope': 'vismanet_erp_interactive_api:create vismanet_erp_interactive_api:delete vismanet_erp_interactive_api:read vismanet_erp_interactive_api:update'
#     },
#     client_kwarg={
#         'scope': 'vismanet_erp_interactive_api:create vismanet_erp_interactive_api:delete vismanet_erp_interactive_api:read vismanet_erp_interactive_api:update'
#     }
# )

@app.route('/')
def index():
    return render_template('index.html')
   
@app.route('/login')
def login():

    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    vismaconnect = OAuth2Session(client_id, 
        redirect_uri="https://127.0.0.1:5000/authorize", 
        scope="vismanet_erp_interactive_api:create vismanet_erp_interactive_api:delete vismanet_erp_interactive_api:read vismanet_erp_interactive_api:update",
        )

    authorization_url, state = vismaconnect.authorization_url(authorize_url,
        code_challenge=code_challenge, 
        code_challenge_method="S256")

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state

    return redirect(authorization_url)    

@app.route('/authorize')    
def authorize():

    code = request.args.get("code")    
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """
    vismaconnect = OAuth2Session(client_id, state=session['oauth_state'])
    token = vismaconnect.fetch_token(token_url,
        client_secret=client_secret,        
        code_verifier=code_verifier,
        code=code
        )

        # authorization_response=request.url,

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    session['oauth_token'] = token

    return redirect('/')