#import required modules 
import socket 
import threading 


HOST="127.0.0.1"
PORT=1234 #from 0 to 65535
Listener_Limit=5

#Main Function

def main():
    #creating the socket class obj
    #AF_INET: ipv4
    #SOCK_STREAM: TCP protocol is going to be used for communication packets
    #SOCK_DGRAM: UDP protocol 

    server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)



    #creating a try catch block
    try:
        #provide the server with host and ip address 

        server.bind((HOST,PORT))
        print(f"the server is running on {HOST} and {PORT}")
    except:
        print(f"unable to bind to {HOST} and {PORT} ")

    #set server limit 

    server.listen(Listener_Limit)

    #this while loop will keep listening on client connections

    while 1:

        client, address=server.accept()
        print(f"successfully connected to client{address[0]} {address[1]}")



if __name__=='__main__':
    main()

