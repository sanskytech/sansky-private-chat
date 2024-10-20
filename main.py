
#from flask import Flask, request, jsonify
#import hashlib
#import jwt
#import datetime
#import time

# Create the Flask app
#app = Flask(__name__)

# Secret key for encoding JWT tokens
#app.config['SECRET_KEY'] = '123'

# the Secret KEY is abusrd 

# Helper function to generate user_id based on user input (name + Group_Name + timestamp)
#def generate_user_id(name, group_name):
    # Create a unique user_id by combining the name, Group_Name, and current timestamp
   # name_group_combination = name + group_name + str(time.time())
  ##  user_id = hashlib.md5(name_group_combination.encode()).hexdigest()
   # return user_id

# Helper function to generate a JWT token, including name and Group_Name
#def generate_token(user_id, name, group_name):
   # token = jwt.encode({
   #     'user_id': user_id,
   #     'name': name,
   #     'group_name': group_name,
   #     'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
   # }, app.config['SECRET_KEY'], algorithm='HS256')
   # return token

# Middleware to protect routes
#def token_required(f):
   # def decorator(*args, **kwargs):
       # token = request.headers.get('x-access-token')
        #if not token:
          #  return jsonify({'message': 'Token is missing!'}), 401
       # try:
            # Decode the token and retrieve user data
           # data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            #current_user_id = data['user_id']
           # current_group_name = data['group_name']
           # current_name = data['name']
        #except:
           # return jsonify({'message': 'Token is invalid!'}), 401
        #return f(current_user_id, current_group_name, current_name, *args, **kwargs)
    #decorator.__name__ = f.__name__
    #return decorator

# Route to generate and return token
#@app.route('/get-token', methods=['POST'])
#def get_token():
    # Expecting the user to send their name and Group_Name in the request body
   # data = request.get_json()
    
    #if 'name' not in data:
       # return jsonify({'error': 'Name is required'}), 400
   # if 'Group_Name' not in data:
        #return jsonify({'error': 'Group_Name is required'}), 400

    # Generate user_id from the name and Group_Name
    #user_id = generate_user_id(data['name'], data['Group_Name'])
    
    # Generate a token for this user
    #token = generate_token(user_id, data['name'], data['Group_Name'])
    
    #return jsonify({'token': token, 'user_id': user_id}), 200

# Protected route to get user data, ensuring the user_id in the token matches the URL user_id
#@app.route('/get-user/<user_id>', methods=['GET'])
#@token_required
#def get_user(current_user_id, current_group_name, current_name, user_id):
    # Ensure that the user_id in the URL matches the current authenticated user_id from the token
   # if current_user_id != user_id:
    #    return jsonify({'error': 'Unauthorized access to user data'}), 403
    
    # Sample user data to return
   # user_data = {
   #     "user_id": user_id,
   #     "name": current_name,
   #     "group_name": current_group_name
   # }
    
    # Add any extra query parameters if provided
   # extra = request.args.get("extra")
   # if extra:
   #     user_data["extra"] = extra
    
   # return jsonify(user_data), 200

# Example protected route to create a user (just a demo for protected routes)
#@app.route('/create-user', methods=['POST'])
#@token_required
#def create_user(current_user_id, current_group_name, current_name):
    #if request.is_json:
       # data = request.get_json()
        
       # if "username" not in data:
          #  return jsonify({"error": "Missing 'username' key in JSON"}), 400
        
       # return jsonify({"message": "User created", "user_id": current_user_id, "data": data}), 201
    #else:
       # return jsonify({"error": "Request must be JSON"}), 400

#if __name__ == "__main__":
    app.run(debug=True, port=5000)



from flask import Flask, request, jsonify
import hashlib
import jwt
import datetime
import time
import os
import secrets
from argon2 import PasswordHasher

# Create the Flask app
app = Flask(__name__)

# Helper function to combine PBKDF2 and Argon2 to derive a secure key
def derive_key(passphrase, salt=None):
    # Generate a salt if one is not provided
    if salt is None:
        salt = os.urandom(32)  # Use 32 bytes for salt

    # Step 1: Apply PBKDF2
    pbkdf2_key = hashlib.pbkdf2_hmac(
        'sha256',              # Hash function
        passphrase.encode(),    # Convert passphrase to bytes
        salt,                  # Salt
        100000,                # Number of iterations
        dklen=32               # Length of the derived key (256 bits)
    )

    # Step 2: Apply Argon2 on the result from PBKDF2
    ph = PasswordHasher(time_cost=2, memory_cost=51200, parallelism=8)
    argon2_key = ph.hash(pbkdf2_key.hex())  # Argon2 processes the PBKDF2 key

    return argon2_key, salt

# Function to generate a secure random passphrase
def generate_random_passphrase(length=32):
    # Generate a random passphrase consisting of letters and digits
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    passphrase = ''.join(secrets.choice(characters) for _ in range(length))
    return passphrase

# Generate a random passphrase for the secret key
passphrase = generate_random_passphrase()
app.config['SECRET_KEY'], _ = derive_key(passphrase)

# Helper function to generate user_id based on user input (name + Group_Name + timestamp)
def generate_user_id(name, group_name):
    # Create a unique user_id by combining the name, Group_Name, and current timestamp
    name_group_combination = name + group_name + str(time.time())
    user_id = hashlib.md5(name_group_combination.encode()).hexdigest()
    return user_id

# Helper function to generate a JWT token, including name and Group_Name
def generate_token(user_id, name, group_name):
    token = jwt.encode({
        'user_id': user_id,
        'name': name,
        'group_name': group_name,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
    }, app.config['SECRET_KEY'], algorithm='HS256')
    return token

# Middleware to protect routes
def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            # Decode the token and retrieve user data
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            current_group_name = data['group_name']
            current_name = data['name']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user_id, current_group_name, current_name, *args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

# Route to generate and return token
@app.route('/get-token', methods=['POST'])
def get_token():
    # Expecting the user to send their name and Group_Name in the request body
    data = request.get_json()
    
    if 'name' not in data:
        return jsonify({'error': 'Name is required'}), 400
    if 'Group_Name' not in data:
        return jsonify({'error': 'Group_Name is required'}), 400

    # Generate user_id from the name and Group_Name
    user_id = generate_user_id(data['name'], data['Group_Name'])
    
    # Generate a token for this user
    token = generate_token(user_id, data['name'], data['Group_Name'])
    
    return jsonify({'token': token, 'user_id': user_id}), 200

# Protected route to get user data, ensuring the user_id in the token matches the URL user_id
@app.route('/get-user/<user_id>', methods=['GET'])
@token_required
def get_user(current_user_id, current_group_name, current_name, user_id):
    # Ensure that the user_id in the URL matches the current authenticated user_id from the token
    if current_user_id != user_id:
        return jsonify({'error': 'Unauthorized access to user data'}), 403
    
    # Sample user data to return
    user_data = {
        "user_id": user_id,
        "name": current_name,
        "group_name": current_group_name
    }
    
    # Add any extra query parameters if provided
    extra = request.args.get("extra")
    if extra:
        user_data["extra"] = extra
    
    return jsonify(user_data), 200

# Example protected route to create a user (just a demo for protected routes)
@app.route('/create-user', methods=['POST'])
@token_required
def create_user(current_user_id, current_group_name, current_name):
    if request.is_json:
        data = request.get_json()
        
        if "username" not in data:
            return jsonify({"error": "Missing 'username' key in JSON"}), 400
        
        return jsonify({"message": "User created", "user_id": current_user_id, "data": data}), 201
    else:
        return jsonify({"error": "Request must be JSON"}), 400

if __name__ == "__main__":
    app.run(debug=True, port=5000)
