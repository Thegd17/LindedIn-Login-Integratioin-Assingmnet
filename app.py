# app.py
import os
import requests
from flask import Flask, redirect, url_for, session, request, render_template
from dotenv import load_dotenv
import jwt # Import PyJWT library for decoding JWTs

# Load environment variables from .env file
# This ensures your sensitive credentials are not hardcoded in the application.
load_dotenv()

app = Flask(__name__)
# Flask's secret key is crucial for session security. It signs the session cookies.
# A strong, random string is required. Get it from your .env file.
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# LinkedIn OpenID Connect Configuration
# These values come from your LinkedIn Developer application settings.
LINKEDIN_CLIENT_ID = os.getenv('LINKEDIN_CLIENT_ID')
LINKEDIN_CLIENT_SECRET = os.getenv('LINKEDIN_CLIENT_SECRET')

# The redirect URI must EXACTLY match one of the "Authorized redirect URIs"
# configured in your LinkedIn application settings.
# For local development, it's typically 'http://127.0.0.1:5000/callback'.
# For deployment, it will be your deployed app's URL (e.g., 'https://your-app-name.onrender.com/callback').
LINKEDIN_REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://127.0.0.1:5000/callback')

# LinkedIn OpenID Connect Endpoints
# These are standard OAuth 2.0 endpoints that also support OIDC.
LINKEDIN_AUTH_URL = 'https://www.linkedin.com/oauth/v2/authorization'
LINKEDIN_TOKEN_URL = 'https://www.linkedin.com/oauth/v2/accessToken'

# Scopes requested for the OpenID Connect flow.
# 'openid': This is mandatory for any OpenID Connect authentication.
# 'profile': Requests access to standard profile claims (like given_name, family_name) within the id_token.
# 'email': Requests access to the user's primary email address claim within the id_token.
LINKEDIN_SCOPES = 'openid profile email'

@app.route('/')
def index():
    """
    The home page of the application.
    Checks if the user is already logged in (by checking for 'linkedin_access_token' in session).
    If logged in, redirects to the profile page; otherwise, displays the login button.
    """
    if 'linkedin_access_token' in session:
        return redirect(url_for('profile'))
    return render_template('login.html')

@app.route('/login')
def login():
    """
    Initiates the LinkedIn OpenID Connect authentication flow.
    Constructs the authorization URL and redirects the user's browser to LinkedIn's login page.
    """
    # Generate a unique 'state' parameter to protect against Cross-Site Request Forgery (CSRF) attacks.
    # This value is stored in the session and verified upon callback.
    state = os.urandom(16).hex()
    session['oauth_state'] = state

    # Construct the authorization URL with all required parameters for OIDC.
    # 'response_type=code' indicates the Authorization Code Flow.
    # 'scope' must include 'openid' for OIDC, along with 'profile' and 'email' for desired claims.
    # Spaces in the scope string must be URL-encoded as '%20'.
    auth_url = (
        f"{LINKEDIN_AUTH_URL}?"
        f"response_type=code&"
        f"client_id={LINKEDIN_CLIENT_ID}&"
        f"redirect_uri={LINKEDIN_REDIRECT_URI}&"
        f"state={state}&"
        f"scope={LINKEDIN_SCOPES.replace(' ', '%20')}"
    )
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """
    Handles the redirect from LinkedIn after the user has authorized the application.
    This endpoint performs the following steps:
    1. Checks for errors returned by LinkedIn.
    2. Validates the 'state' parameter to prevent CSRF.
    3. Exchanges the authorization code for an access token and an ID token.
    4. Decodes the ID token to extract user profile and email information.
    5. Stores relevant user data in the Flask session.
    6. Redirects the user to their profile page.
    """
    # Extract parameters from the callback URL query string
    code = request.args.get('code') # The authorization code provided by LinkedIn
    state = request.args.get('state') # The state parameter to verify against CSRF
    error = request.args.get('error') # Any error code from LinkedIn (e.g., user denied access)
    error_description = request.args.get('error_description') # Detailed error message

    # 1. Handle errors returned by LinkedIn (e.g., user denied access or invalid request)
    if error:
        app.logger.error(f"LinkedIn OIDC Error: {error} - {error_description}")
        return render_template('error.html', message=f"Login failed: {error_description}")

    # 2. Validate the 'state' parameter to prevent CSRF attacks.
    # The 'state' received in the callback must match the one stored in the session.
    if state != session.pop('oauth_state', None):
        app.logger.error("CSRF attack detected: State mismatch.")
        return render_template('error.html', message="Login failed: Invalid state parameter.")

    # 3. Ensure an authorization code was successfully received.
    if not code:
        app.logger.error("No authorization code received from LinkedIn.")
        return render_template('error.html', message="Login failed: No authorization code.")

    # 4. Exchange the authorization code for an access token and an ID token.
    # This is a server-to-server POST request to LinkedIn's token endpoint.
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': LINKEDIN_REDIRECT_URI,
        'client_id': LINKEDIN_CLIENT_ID,
        'client_secret': LINKEDIN_CLIENT_SECRET,
    }
    try:
        token_response = requests.post(LINKEDIN_TOKEN_URL, data=token_data)
        token_response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)
        response_json = token_response.json()
        access_token = response_json.get('access_token')
        id_token = response_json.get('id_token') # The JSON Web Token (JWT) containing user claims
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error exchanging code for token: {e}")
        return render_template('error.html', message="Login failed: Could not obtain access token/id_token.")

    # 5. Verify that both the access_token and id_token were received.
    if not access_token:
        app.logger.error("Access token not found in LinkedIn response.")
        return render_template('error.html', message="Login failed: Access token missing.")

    if not id_token:
        app.logger.error("ID token not found in LinkedIn response. Ensure 'openid' scope is requested and LinkedIn app is configured for OIDC.")
        return render_template('error.html', message="Login failed: ID token missing.")

    # Store the access token in the session. This token can be used for subsequent API calls
    # to LinkedIn if more data than what's in the ID token is needed.
    session['linkedin_access_token'] = access_token

    # 6. Decode the ID token to extract user claims (profile and email information).
    try:
        # IMPORTANT: For a production application, you MUST verify the ID token's signature.
        # This involves fetching LinkedIn's public keys (JWKS) from their OpenID Connect
        # discovery endpoint and using them to verify the token.
        # For simplicity in this example, we are decoding without signature verification,
        # assuming the token is authentic as it comes directly from LinkedIn's token endpoint.
        decoded_id_token = jwt.decode(id_token, options={"verify_signature": False})

        # Extract standard OpenID Connect claims from the decoded JWT
        session['user_id'] = decoded_id_token.get('sub', 'N/A') # 'sub' is the unique subject identifier (user ID)
        session['first_name'] = decoded_id_token.get('given_name', 'N/A')
        session['last_name'] = decoded_id_token.get('family_name', 'N/A')
        session['email'] = decoded_id_token.get('email', 'N/A') # The user's primary email address

    except jwt.exceptions.DecodeError as e:
        app.logger.error(f"Error decoding ID token: {e}")
        # Provide default values in case of a decoding error to prevent app crash
        session['first_name'] = 'Error'
        session['last_name'] = 'Decoding Token'
        session['email'] = 'Error'
        session['user_id'] = 'Error'
        return render_template('error.html', message="Login failed: Could not decode user information from ID token.")

    # Upon successful authentication and data retrieval, redirect to the profile page.
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    """
    Displays the user's profile information retrieved from LinkedIn.
    This page is protected; if the user is not logged in, they are redirected to the home page.
    """
    if 'linkedin_access_token' not in session:
        return redirect(url_for('index')) # Redirect to login if not authenticated

    # Retrieve user data from the Flask session to display on the profile page.
    user_data = {
        'first_name': session.get('first_name', 'N/A'),
        'last_name': session.get('last_name', 'N/A'),
        'email': session.get('email', 'N/A'),
        'user_id': session.get('user_id', 'N/A')
    }
    return render_template('profile.html', user=user_data)

@app.route('/logout')
def logout():
    """
    Clears the user's Flask session, effectively logging them out of the application,
    and then redirects them to the home page.
    """
    session.clear() # Removes all data from the current user's session
    return redirect(url_for('index'))

if __name__ == '__main__':
    # This block runs the Flask development server when the script is executed directly.
    # For production deployment, a WSGI server like Gunicorn (included in requirements.txt)
    # should be used instead of app.run().
    # debug=True enables the reloader and debugger, which are useful during development.
    # Set debug=False for production environments for security and performance.
    app.run(debug=True)
