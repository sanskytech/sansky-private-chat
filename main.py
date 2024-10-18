#from flask import Flask, request, jsonify 
#from flask_jwt_extended import JWTManager, create_access_token, jwt_required

#creating our Flask app

#app=Flask(__name__)

# Configure the secret key for JWT
#app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change this!
#jwt = JWTManager(app)

#using the same name of the app for creating route


# the path parameter < user_id > is the same with the get use arg
#@app.route("/get-user/<user_id>")
#def get_user(user_id):
   # user_data = {
    #    "user_id": user_id,
    #    "name": "John Doe",
    #    "email": "John.doe@example.com"
   # }
# "get-user/123?extra=hello world " the query can be get with the following command

  #  extra= request.args.get("extra")
 #   if extra:
  #      user_data["extra"]=extra
# we give info as json data to user 
    #return jsonify(user_data), 200 



#@app.route("/create-user", methods=["POST"])
#def create_user():
    # Check if the request has JSON data
 #   if request.is_json:
        # Get the JSON data
  #      data = request.get_json()
        
        # You can add additional validation for the data here if needed
        # For example, checking if 'username' is present
  #      if "username" not in data:
  #          return jsonify({"error": "Missing 'username' key in JSON"}), 400
        
        # Return the received data with a 201 status code
 #       return jsonify(data), 201
 #   else:
#        return jsonify({"error": "Request must be JSON"}), 400


#@app.route("/create-user",methods=["POST"])
#def create_user():

    #if request.method=="POST":
 #   data= request.get_json()

  #  return jsonify(data), 201 



#if __name__== "__main__":
#    app.run(debug=True)



from flask import Flask, request, jsonify
import hashlib
import jwt
import datetime
import time

# Create the Flask app
app = Flask(__name__)

# Secret key for encoding JWT tokens
app.config['SECRET_KEY'] = '123'

# the Secret KEY is abusrd 

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
        except:
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
