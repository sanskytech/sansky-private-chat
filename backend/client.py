#import required modules 

import socket
import threading 

HOST="127.0.0.1"
PORT=1234

#main function
def main():
    #creating a socket obj
    #the AF_INET and SOCKET_STREAM is used because the communication protocols of the client and server must match 
    client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    #connect to the server
    try:
        client.connect((HOST,PORT))
        print("successfully connected to server")
    except:
        print(f"unable to connect to server {HOST} {PORT}")

    #




if __name__=='__main__':
    main()