import socket
import sys
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

#This function takes a string as parameter
#and returns an encrypted version of the string.
def encry(message):
	#Generate key
        keyLen =128
        key = get_random_bytes(int(keyLen/8))

	#Generate Cyphering Block
        cipher = AES.new(key, AES.MODE_ECB)

	#Encrypt the message
        ct_bytes = cipher.encrypt(pad(message.encode('ascii'),16))
        print("The encrypted message:", ct_bytes)
	
        return ct_bytes

#Function takes an encrypted string as parameter
#and returns the decrypted version of the string.
def decry(message):
	#Generate key
        keyLen = 128
        key = get_random_bytes(int(keyLen/8))

	#Generate Cyphering
        cipher = AES.new(key, AES.MODE_ECB)

	#Decrypt message
        padded_message = cipher.decrypt(message)
        print(padded_message)
	#Remove padding
        Encodedmessage = unpad(padded_message,16)

        #The encrypted and decrypted messages are printed 
        print("Encrypted message:", message)
        print("Decrypted message:", Encodedmessage.decode('ascii'))

        return Encodedmessage.decode('ascii')

def server():
    #Server port
    serverPort = 13000
    
    #Create server socket that uses IPv4 and TCP protocols
    try:
        serverSocket = socket.socket(socket.AF_INET, 
socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    #Associate 13000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)
        
    print('The server is ready to accept connections')
        
    #The server can only have one connection in its queue waiting 
    #for acceptance
    serverSocket.listen(5)
        
    while 1:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            print(addr,' ',connectionSocket)
            pid = os.fork()
            
            # If it is a client process
            if pid== 0:
                
                serverSocket.close()
                
                #There are only a few client names allowed.
                #Those allowed clients are kept in a list called validList.
                validList = ["client1", "client2", "client3"]

                #Server send welcome message to client, and asked for name.
                connectionSocket.send(("Welcome to the system\nWhat is your name?").encode('ascii'))
                
                #server receives name and check if name is valid.
                clientName = (connectionSocket.recv(2048)).decode('ascii')
                print("Name is", clientName)
                

                connectionSocke.close()
                
                return
            
            #Parent doesn't need this connection
            connectionSocket.close()
            
        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close()
            sys.exit(1)
        except:
            print('Goodbye')
            serverSocket.close()
            sys.exit(0)
            
        
#-------
server()
