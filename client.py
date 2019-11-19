import socket
import sys

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

#This function takes a string as parameter.
#and returns as encrypted version of the string.
def encry(message, key):

	#Generate Cyphering Block
        cipher = AES.new(key, AES.MODE_ECB)

	#Encrypt the message
        ct_bytes = cipher.encrypt(pad(message,16))
        print("The encrypted message:", ct_bytes)
        
        return ct_bytes

def decry(message, key):
	#Generate ciphering
        cipher = AES.new(key, AES.MODE_ECB)

	#Decrypt message
        Padded_message = cipher.decrypt(message)
	#Remove padding
        decryMessage = unpad(Padded_message,16)

        return decryMessage

def encryRSA(message, clientName):
    filename = clientName+"_public.pem"
    f=open(filename, "rb")
    for line in f:
        print(line)

def client():
    # Server Information
    serverName = '127.0.0.1' #'localhost'
    serverPort = 13000
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        clientSocket.connect((serverName,serverPort))
        
        # Client receives welcome message and prompted to input name. 
        welcomeMessage = clientSocket.recv(2048)
        print(welcomeMessage.decode('ascii'))

        #Client sends name to server
        clientName = input("Enter your client name:").encode('ascii')
        clientSocket.send(clientName)
        
        # Client terminate connection with the server
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
#client()
encryRSA("hello", "client1")

