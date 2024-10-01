from flask import Flask, request, jsonify 

#creating our Flask app

app=Flask(__name__)

#using the same name of the app for creating route

@app.route("/")
def home():
    return "Home"





if __name__== "__main__":
    app.run(debug=True)