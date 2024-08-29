# importing required modules
from flask import Flask, render_template 
from flask_socketio import join_room, leave_room, send, SocketIO
import random 
from string import ascii_uppercase 


app=Flask(__name__)
app.config["SECRET_KEY"]="Sansky"
socketio= SocketIO(app)


#creating two routes 
#first route for the home page of the chatroom
#second route for the room page (chatroom)

@app.route("/",methods=["POST","GET"])

def home():
    return render_template("home.html")



if __name__== "__main__":
    socketio.run(app,debug=True)

