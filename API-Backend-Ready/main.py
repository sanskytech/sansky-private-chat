from flask import Flask, request, jsonify
import hashlib
import jwt
import datetime
import time
import os
import secrets
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Create the Flask app
app = Flask(__name__)

# Set the secret key for JWT encoding
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Random secret key

# Generate RSA keys for JWE
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Helper function to generate a random AES key (256 bits)
def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key

# Function to encrypt data using AES
def encrypt_with_aes(data, aes_key):
    iv = os.urandom(16)  # 128-bit IV for AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Ensure data is in bytes, encode if it's a string
    if isinstance(data, str):
        data = data.encode()

    # Padding to ensure data length is a multiple of 16
    padding_length = 16 - len(data) % 16
    data += bytes([padding_length]) * padding_length
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    return iv + ciphertext  # Return IV + ciphertext to allow decryption

# Function to encrypt AES key using RSA
def encrypt_aes_key_with_rsa(aes_key):
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

# Helper function to generate user_id based on user input (name + Group_Name + timestamp)
def generate_user_id(name, group_name):
    name_group_combination = name + group_name + str(time.time())
    user_id = hashlib.md5(name_group_combination.encode()).hexdigest()
    return user_id

# Function to generate a JWT token and encrypt it using AES
def generate_token(user_id, name, group_name):
    token = jwt.encode({
        'user_id': user_id,
        'name': name,
        'group_name': group_name,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expires in 1 hour
    }, app.config['SECRET_KEY'], algorithm='HS256')

    # Generate AES key and encrypt the token data
    aes_key = generate_aes_key()
    encrypted_token = encrypt_with_aes(token, aes_key)
    
    # Encrypt the AES key using RSA
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key)
    
    # Concatenate encrypted AES key and encrypted token together
    encrypted_data = encrypted_aes_key + encrypted_token
    
    return encrypted_data

# AES decryption function
def decrypt_with_aes(aes_key, encrypted_data):
    iv = encrypted_data[:16]  # First 16 bytes are the IV
    ciphertext = encrypted_data[16:]  # The rest is the ciphertext
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]
    
    return decrypted_data

# Middleware to protect routes
def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('x-access-token')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Ensure the token is in bytes if it's in hex format
            encrypted_data = bytes.fromhex(token)

            # Separate the encrypted AES key and encrypted token
            encrypted_aes_key = encrypted_data[:256]  # Assuming RSA encrypted AES key is 256 bytes
            encrypted_token = encrypted_data[256:]

            # Decrypt the AES key using RSA private key
            decrypted_aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt the token using the decrypted AES key
            decrypted_token = decrypt_with_aes(decrypted_aes_key, encrypted_token)

            # Decode the JWT token
            data = jwt.decode(decrypted_token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            current_group_name = data['group_name']
            current_name = data['name']
        except Exception as e:
            print(f"Decryption or decoding failed: {e}")
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user_id, current_group_name, current_name, *args, **kwargs)
    decorator.__name__ = f.__name__
    return decorator

# Route to generate and return encrypted token
@app.route('/get-token', methods=['POST'])
def get_token():
    data = request.get_json()
    
    if 'name' not in data:
        return jsonify({'error': 'Name is required'}), 400
    if 'Group_Name' not in data:
        return jsonify({'error': 'Group_Name is required'}), 400

    user_id = generate_user_id(data['name'], data['Group_Name'])
    
    encrypted_data = generate_token(user_id, data['name'], data['Group_Name'])
    
    return jsonify({
        'encrypted_data': encrypted_data.hex(),
        'user_id': user_id
    }), 200

# Route to exchange public keys
@app.route('/exchange-public-key', methods=['POST'])
@token_required
def exchange_public_key(current_user_id, current_group_name, current_name):
    data = request.get_json()

    # Ensure the public key is provided
    if 'public_key' not in data:
        return jsonify({'error': 'Public key is required'}), 400

    # Here, you can store the public key in a session or temporary storage
    # but for now, we just return a success message
    return jsonify({'message': 'Public key received successfully'}), 200

# Route to send encrypted messages
@app.route('/send-message', methods=['POST'])
@token_required
def send_message(current_user_id, current_group_name, current_name):
    data = request.get_json()

    if 'recipient_id' not in data or 'encrypted_message' not in data:
        return jsonify({'error': 'Recipient ID and encrypted message are required'}), 400
    
    # For simplicity, we'll assume the message is forwarded without modification.
    # You can store the message and encrypted content as needed (e.g., in a DB).
    return jsonify({'message': 'Encrypted message sent successfully'}), 200

# Route to receive encrypted messages
@app.route('/receive-message', methods=['GET'])
@token_required
def receive_message(current_user_id, current_group_name, current_name):
    # Here, retrieve the encrypted messages from a storage system
    # (assuming the encrypted messages are already stored)
    encrypted_messages = [
        {'encrypted_message': 'base64_encoded_encrypted_message_1'},
        {'encrypted_message': 'base64_encoded_encrypted_message_2'}
    ]
    
    return jsonify({'messages': encrypted_messages}), 200

# Route to get user data, ensuring the user_id in the token matches the URL user_id
@app.route('/get-user/<user_id>', methods=['GET'])
@token_required
def get_user(current_user_id, current_group_name, current_name, user_id):
    if current_user_id != user_id:
        return jsonify({'error': 'Unauthorized access to user data'}), 403
    
    user_data = {
        "user_id": user_id,
        "name": current_name,
        "group_name": current_group_name
    }
    extra = request.args.get("extra")
    if extra:
        user_data["extra"] = extra
    
    return jsonify(user_data), 200

# Example protected route to create a user
@app.route('/create-user', methods=['POST'])
@token_required
def create_user(current_user_id, current_group_name, current_name):
    if request.is_json:
        data = request.get_json()
        
        if "username" not in data:
            return jsonify({"error": "Missing 'username' key in JSON"}), 400
        
        # You can add user creation logic here, such as saving the user in a database
        return jsonify({"message": "User created", "user_id": current_user_id, "data": data}), 201
    else:
        return jsonify({"error": "Request must be JSON"}), 400

if __name__ == "__main__":
    app.run(debug=True, port=5000)
