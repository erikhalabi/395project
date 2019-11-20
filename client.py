import socket
import sys

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
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

#This is the RSA encrypting function, using the public key
#It takes 2 parameters: The message to be encrypted
# and the client name(or server) and it gets the key from the 
# required .pem file.
#The encrypted message is then encoded.
#It returns the encoded message.
def encryRSA(message, clientName):
    filename = clientName+"_public.pem"
    f=open(filename, "rb")
    public_key = f.read()
    pubkey = RSA.import_key(public_key)
    cipher_rsa_en = PKCS1_OAEP.new(pubkey)
    enc_data = cipher_rsa_en.encrypt(message.encode('ascii'))
    
    return enc_data

#This is the RSA encrypting function, using private key.
#It takes 2 parameters: The message to be decrypted
# and the client name(or server) and it gets the key from the
# required .pem file.
#The message is decoded and then decrypted.
#It returns the decrypted message.
def decryRSA(message, clientName):
    filename = clientName+"_private.pem"
    f = open(filename, "rb")
    private_key = f.read()
    priv_key = RSA.import_key(private_key)
    cipher_rsa_dec = PKCS1_OAEP.new(priv_key)
    dec_data = cipher_rsa_dec.decrypt(message)
    print(dec_data.decode('ascii'))

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
        clientName = input("Enter your client name:")
        clientName = encryRSA(clientName, "server")
        clientSocket.send(clientName)
        



        # Client terminate connection with the server
        clientSocket.close()
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()


