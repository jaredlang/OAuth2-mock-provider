from flask import Flask, request, jsonify, redirect
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace this with a real secret key

# In-memory data stores
users = {
    "user1": {"password": "password1", "scope": "Salesforce"},
    "user2": {"password": "password2", "scope": "Mahattan"}
}
clients = {
    "client_id_1": {"client_secret": "client_secret_1", "redirect_uri": "http://localhost:5001/callback"}
}
auth_codes = {}
tokens = {}

# Token expiration settings
ACCESS_TOKEN_EXPIRATION = timedelta(minutes=5)      # 5 minutes
REFRESH_TOKEN_EXPIRATION = timedelta(minutes=30)    # 30 minutes

@app.route('/health')
def health(): 
    return "OK", 200

def generate_token():
    return str(uuid.uuid4())


def is_token_expired(token_data):
    return datetime.utcnow() > token_data['expires_at']


@app.route('/authorize', methods=['GET', 'POST'])
def authorize():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')

        # Check user credentials
        if username in users and users[username]['password'] == password:
            auth_code = generate_token()
            auth_codes[auth_code] = {
                'client_id': client_id,
                'username': username,
                'redirect_uri': redirect_uri
            }
            return redirect(f"{redirect_uri}?code={auth_code}")
        else:
            return "Invalid credentials", 401

    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    if client_id not in clients or clients[client_id]['redirect_uri'] != redirect_uri:
        return "Invalid client or redirect URI", 400

    return '''
        <h1>OAuth2 Login</h1> 
        <form method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Authorize</button>
        </form>
    '''


@app.route('/token', methods=['POST'])
def token():
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    code = request.form.get('code')
    grant_type = request.form.get('grant_type')
    refresh_token = request.form.get('refresh_token')

    # Check client credentials
    if client_id not in clients or clients[client_id]['client_secret'] != client_secret:
        return "Invalid client credentials", 401

    if grant_type == 'authorization_code':
        # Check authorization code
        if code not in auth_codes or auth_codes[code]['client_id'] != client_id:
            return "Invalid authorization code", 401

        # Generate access and refresh tokens
        access_token = generate_token()
        refresh_token = generate_token()
        tokens[access_token] = {
            'username': auth_codes[code]['username'],
            'scope': users[auth_codes[code]['username']]['scope'],
            'expires_at': datetime.utcnow() + ACCESS_TOKEN_EXPIRATION,
            'refresh_token': refresh_token
        }

        # Return token response
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': ACCESS_TOKEN_EXPIRATION.total_seconds(),
            'refresh_token': refresh_token,
            'scope': tokens[access_token]['scope']
        })

    elif grant_type == 'refresh_token':
        # Validate refresh token
        for token_data in tokens.values():
            if token_data['refresh_token'] == refresh_token:
                if is_token_expired(token_data):
                    return "Refresh token expired", 401

                # Generate new access token
                access_token = generate_token()
                tokens[access_token] = {
                    'username': token_data['username'],
                    'scope': token_data['scope'],
                    'expires_at': datetime.utcnow() + ACCESS_TOKEN_EXPIRATION,
                    'refresh_token': refresh_token
                }

                # Return new access token
                return jsonify({
                    'access_token': access_token,
                    'token_type': 'Bearer',
                    'expires_in': ACCESS_TOKEN_EXPIRATION.total_seconds(),
                    'refresh_token': refresh_token,
                    'scope': tokens[access_token]['scope']
                })

        return "Invalid refresh token", 401

    return "Invalid grant type", 400


@app.route('/userinfo', methods=['GET'])
def userinfo():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return "Authorization header missing", 401

    access_token = auth_header.split()[1]
    if access_token not in tokens:
        return "Invalid access token", 401

    if is_token_expired(tokens[access_token]):
        return "Access token expired", 401

    user_data = tokens[access_token]
    return jsonify({
        'username': user_data['username'],
        'scope': user_data['scope']
    })


if __name__ == '__main__':
    app.run(debug=True)
