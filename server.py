#-------------------------------------------------------------
# Names: Bhavish Bhunjun, Erik Halabi, Dhaneshen Moonain
# Program: server.py
#-------------------------------------------------------------

import socket
import sys
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


#This function takes a string and key as parameter
#and returns an encrypted version of the string.
def encryAES(message, key):
        #Generate Cyphering Block
        cipher = AES.new(key, AES.MODE_ECB)

	#Encrypt the message
        ct_bytes = cipher.encrypt(pad(message.encode('ascii'), 16))
        print("The encrypted message:", ct_bytes)
	
        return ct_bytes

#Function takes an encrypted string and key as parameter
#and returns the decrypted version of the string.
def decryAES(message, key):

	#Generate Cyphering
        cipher = AES.new(key, AES.MODE_ECB)

	#Decrypt message
        padded_message = cipher.decrypt(message)
        print(padded_message)
	#Remove padding
        Encodedmessage = unpad(padded_message, 16)

        #The encrypted and decrypted messages are printed 
        print("Encrypted message:", message)
        print("Decrypted message:", Encodedmessage.decode('ascii'))

        return Encodedmessage.decode('ascii')

# This is the RSA encrypting function, using the public key.
# It takes 2 paramters: The message to be encrypted
# and the client name(or server) and it gets the key form the
# required file.
# It returns the encrypted message.
def encryRSA(message, clientName):
        filename = clientName + "_public.pem"
        f = open(filename, "rb")
        public_key = f.read()
        pubkey = RSA.import_key(public_key)
        cipher_rsa_en = PKCS1_OAEP.new(pubkey)
        #enc_data = cipher_rsa_en.encrypt(message.encode('ascii'))

        enc_data = cipher_rsa_en.encrypt(message)
        f.close()
 
        return enc_data

#This is the RSA decrypting function, using private key.
#It takes 2 parameters: The message to be decrypted and the client name(or server) and it gets the key from the 
# required .pem file.
#It returns the decrypted message.
def decryRSA(message, client):
        filename = client + "_private.pem"
        f = open(filename, "rb")
        private_key = f.read()
        priv_key = RSA.import_key(private_key)
        cipher_rsa_dec = PKCS1_OAEP.new(priv_key)
        dec_data = cipher_rsa_dec.decrypt(message)
        f.close()
        return dec_data.decode('ascii')

def getFile(fileName, data):
        f.open(fileName, "w")
        while (data):
                f.write(data)
                data = connectionSocket.recv(2048)
        f.close()
        return data

def server():
        #Server port
        serverPort = 13000
    
        #Create server socket that uses IPv4 and TCP protocols
        try:
                serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
                print('Error in server socket creation:',e)
                sys.exit(1)
    
        #Associate 13000 port number to the server socket
        try:
                serverSocket.bind(('', serverPort))
        except socket.error as e:
                print('Error in server socket binding:',e)
                sys.exit(1)

        # Determine the max file size
        MAX_FILE_SIZE = input("Enter the permitted file size: ")
        
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
                        if pid == 0:
                
                                serverSocket.close()
                
                                #There are only a few client names allowed.
                                #Those allowed clients are kept in a list called validList.
                                validList = ["client1", "client2", "client3"]

                                #Server send welcome message to client, and asked for name.
                                #connectionSocket.send(("Enter client name: ").encode('ascii'))

                                #server receives name and check if name is valid.
                                clientName = connectionSocket.recv(2048)
                                clientNameDecry = decryRSA(clientName, "server")

                                if clientNameDecry in validList:
                                        connectionSocket.send("Valid".encode('ascii'))
                                # The client name is not valid, 
                                # Appropriate message is sent to client and connection is 
                                # terminated
                                else:
                                        connectionSocket.send("Invalid clientName".encode('ascii'))
                                        print("The received client",clientNameDecry,"is invalid.(Connection Terminated.)")
                                        connectionSocket.close()
                                        return

                                # Otherwise we continue with our program.
                                # A 256 AES key called sym_key is generated
                                # The sym_key is encrypted with the corresponding
                                # client public key and sent to the client.
                                KeyLen = 256
                                sym_key = get_random_bytes(int(KeyLen/8))
                                sym_key_Encry = encryRSA(sym_key, clientNameDecry)
                                connectionSocket.send(sym_key_Encry)
                                print("Connection Accepted and Symmetric Key Generated for client:", clientNameDecry)

                                # Server sends message to client, asking for file name.
                                # Message is encrypted using AES.
                                message = "Enter Filename:"
                                messageEncry = encryAES(message, sym_key)
                                connectionSocket.send(messageEncry)

                                # Server receives filename.
                                filenameEncry = connectionSocket.recv(2048)
                                filename = decryAES(filenameEncry, sym_key)
                                print("The Server recieved file name", filename, "from client", clientNameDecry)

                                # Send encrypted message to client
                                reqFileSize = "Server Requested file size"
                                connectionSocket.send(encryAES(reqFileSize, sym_key))

                                # Receive encrypted file size from client and decode it
                                fileSizeEncry = connectionSocket.recv(2048)
                                fileSize = decryAES(fileSizeEncry, sym_key)
                                # Converts it to an interger 
                                fileSize = int(fileSize)
                                
                                # When the message size is larger than the limit send a message to the client and close
                                # the connection, when file is not too big recieve all of it, decode it, and save it
                                if (fileSize > MAX_FILE_SIZE):
                                        # Send message that file is too big 
                                        fileSizeMsg = "The file size is too large."
                                        connectionSocket.send(encryAES(fileSizeMsg, sym_key))
                                        # Close the connection and inform the client of it 
                                        print("File size exceeds the threshold. Terminating connection with", clientNameDecry)
                                        connectionSocket.close()
                                        return
                                else:
                                        # Send encrypted message to client that file size if within limit
                                        fileSizeMsg = "The file size is OK."
                                        connectionSocket.send(encryAES(fileSizeMsg, sym_key))
                                        print("Uploading data from:", clientNameDecry)
                                        # Receive file data from client and decode it 
                                        encryptedData = connectionSocket.recv(2048)
                                        data = decryAES(encryptedData, sym_key)
                                        
                                        # Open file for writing 
                                        f = open(filename, "wb")
                                        # If there is anymore data to be recieved from the file get it and write it 
                                        while (data):
                                                f.write(data)
                                                EncryptedData = connectionSocket.recv(2048)
                                                data = decryAES(encryptedData, sym_key)
                                        f.close() 
                                        recvFile = decryAES(data, sym_key)
                                        print("Upload complete from:", clientNameDecry)
                                        
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
