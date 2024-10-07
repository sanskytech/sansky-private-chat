from flask import Flask, request, jsonify 

#creating our Flask app

app=Flask(__name__)

#using the same name of the app for creating route


# the path parameter < user_id > is the same with the get use arg
@app.route("/get-user/<user_id>")
def get_user(user_id):
    user_data = {
        "user_id": user_id,
        "name": "John Doe",
        "email": "John.doe@example.com"
    }
# "get-user/123?extra=hello world " the query can be get with the following command

    extra= request.args.get("extra")
    if extra:
        user_data["extra"]=extra
# we give info as json data to user 
    return jsonify(user_data), 200 



@app.route("/create-user", methods=["POST"])
def create_user():
    # Check if the request has JSON data
    if request.is_json:
        # Get the JSON data
        data = request.get_json()
        
        # You can add additional validation for the data here if needed
        # For example, checking if 'username' is present
        if "username" not in data:
            return jsonify({"error": "Missing 'username' key in JSON"}), 400
        
        # Return the received data with a 201 status code
        return jsonify(data), 201
    else:
        return jsonify({"error": "Request must be JSON"}), 400


#@app.route("/create-user",methods=["POST"])
#def create_user():

    #if request.method=="POST":
 #   data= request.get_json()

  #  return jsonify(data), 201 



if __name__== "__main__":
    app.run(debug=True)