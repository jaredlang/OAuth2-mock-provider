from flask import Flask, request, jsonify, redirect
import jwt
import time
import uuid

app = Flask(__name__)

# In-memory data stores
users = {
    "user1": {"password": "password1", "scope": "Salesforce"},
    "user2": {"password": "password2", "scope": "Mahattan"}
}
clients = {
    "client_id_1": {"client_secret": "client_secret_1", "redirect_uri": "http://localhost:5001/callback"}, 
    "client_id_2": {"client_secret": "client_secret_2", "redirect_uri": "http://oauth2testapp.azurewebsites.net/callback"}
}
auth_codes = {}
tokens = {}

# jwt secret key
JWT_SECRET_KEY = "jwt_secret_key"

# Token expiration settings
ACCESS_TOKEN_EXPIRATION = 60 * 5      # 5 minutes
REFRESH_TOKEN_EXPIRATION = 60 * 30    # 30 minutes


@app.route('/')
def home(): 
    return "Home Page - OAuth2 Mock Provider", 200

@app.route('/health')
def health(): 
    return "OK", 200

def generate_token():
    return str(uuid.uuid4())


def is_token_expired(token_data):
    return time.time() > token_data['expires_at']


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
    redirect_uri = request.form.get('redirect_uri')
    client_secret = request.form.get('client_secret')
    auth_code = request.form.get('auth_code')
    grant_type = request.form.get('grant_type')
    refresh_token = request.form.get('refresh_token')

    # Check client credentials
    if client_id not in clients or clients[client_id]['client_secret'] != client_secret:
        return "Invalid client credentials", 401

    if grant_type == 'authorization_code':  
        if client_id in clients and clients[client_id]['client_secret'] == client_secret:
            if auth_code in auth_codes and auth_codes[auth_code]['redirect_uri'] == redirect_uri:
                access_token = jwt.encode({
                    'sub': auth_codes[auth_code]['username'],
                    'client_id': client_id,
                    'exp': time.time() + ACCESS_TOKEN_EXPIRATION
                }, JWT_SECRET_KEY, algorithm='HS256')

                refresh_token = generate_token()  # Generate a refresh token
                tokens[access_token] = {
                    'client_id': client_id,
                    'username': auth_codes[auth_code]['username'],
                    'refresh_token': refresh_token
                }

                return jsonify({
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'expires_in': ACCESS_TOKEN_EXPIRATION
                })
            
            return "Invalid authorization code", 401
        
        return "Invalid client id or secret code", 401

    elif grant_type == 'refresh_token':
        refresh_token = request.form.get('refresh_token')

        for token, data in tokens.items():
            if data.get('refresh_token') == refresh_token and data['client_id'] == client_id:
                access_token = jwt.encode({
                    'sub': data['username'],
                    'client_id': client_id,
                    'exp': time.time() + ACCESS_TOKEN_EXPIRATION
                }, JWT_SECRET_KEY, algorithm='HS256')

                return jsonify({
                    'access_token': access_token,
                    'expires_in': 600
                })
            
        return "Invalid refresh token", 401

    return "Invalid grant type", 400


@app.route('/introspect', methods=['POST'])
def introspect():
    token = request.form.get('token')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')

    if client_id in clients and clients[client_id]['client_secret'] == client_secret:
        try:
            decoded = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
            return jsonify({'active': True, 'username': decoded['sub'], 'client_id': decoded['client_id']})
        except jwt.ExpiredSignatureError:
            return jsonify({'active': False, 'error': 'Token expired'})
        except jwt.InvalidTokenError:
            return jsonify({'active': False, 'error': 'Invalid token'})

    return jsonify({'active': False, 'error': 'Invalid client credentials'}), 400


if __name__ == '__main__':
    app.run(debug=True)
