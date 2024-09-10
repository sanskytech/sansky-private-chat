# importing required modules
from flask import Flask, render_template, redirect , session , request , url_for
from flask_socketio import join_room, leave_room, send, SocketIO
import random 
from string import ascii_uppercase 


app=Flask(__name__)
app.config["SECRET_KEY"]="Sansky"
socketio= SocketIO(app)


#creating two routes 
#first route for the home page of the chatroom
#second route for the room page (chatroom)


#the variable rooms is created here because after creating a unqie code we will check if that
# unique code exists in the previos rooms if that exists then we will create another code 
#if that does not exist we will get the code :) 
rooms={}

def generate_unique_code(length):
    while True:
        code=""
        for _ in range(length):
            code += random.choice(ascii_uppercase)
        if code not in rooms:
            break
    
    return code 






@app.route("/",methods=["POST","GET"])

def home():
    session.clear()

    if request.method == "POST":
        name=request.form.get("name")
        code=request.form.get("code")
        join=request.form.get("join", False)
        create=request.form.get("create", False)

        if not name:
             return render_template("home.html", error="Please Enter a Name.",code=code , name=name)

        if join != False and not code:
            return render_template("home.html", error="Please Enter a room code." , code=code , name=name)
        
        #if they are creating the room 

        room=code 
        if create!=False:
            room= generate_unique_code(4)
            rooms[room]={"members":0 ,"messages":[]}


        #if they are not creating the room and wants to join but their code does not belong to any room
        elif code not in rooms:
            return render_template("home.html", error="Room does not exist." , code=code , name=name)



        #we are not storing the info in a database rather in a session
        #we store the name and room of the user in the session 
        # it helps that the user does not need to refresh the page constatnly 
        # instead we save their data in the session
        session["name"]=name 
        session["room"]=room

        #after storing the info in the session we need to redirect the user to chat room


        return redirect(url_for("room"))



    return render_template("home.html")

@app.route("/room")

def room():
    room=session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return(redirect(url_for("home")))
    return render_template("room.html")


@socketio.on("connect")
def connect(auth):
    room=session.get("room")
    name=session.get("name")
    # here if the user is trying to get access to our rooms 
    #with out being in the home page first 
    if not room or not name:
        return
    #here if the user was in invalid room then it will direct the user
    #to the outisde of the room
    if room not in rooms:
        leave_room(room)
        return

    join_room(room) 
    # here after the person joins the room then there will be 
    # a message sent to all of the users in the room 
    # that says that hey mohammad has entered the room 
    send({"name":name , "message":"has entered the room"}, to=room)
    rooms[room]["members"] +=1
    print(f"{name} joined the room {room}")


@socketio.on("disconnect")
def disconnect():
    room=session.get("room")
    name=session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -=1
        #if the number of people is 0 then we delete the room then
        if rooms[room]["members"] <=0:
            del rooms[room]
    
    #sending a message to room that user has left the room
    send({"name":name , "message":"has left the room"}, to=room)
    print(f"{name} has left the room {room}")
    


if __name__== "__main__":
    socketio.run(app,debug=True)

