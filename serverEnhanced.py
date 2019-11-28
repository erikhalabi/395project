# -------------------------------------------------------------
# Names: Bhavish Bhunjun, Erik Halabi, Dhaneshen Moonain
# Program: server.py
# -------------------------------------------------------------

import socket
import sys
import os
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


# This function takes a string and key as parameter
# and returns an encrypted version of the string.
def encryAES(message, key):
    # Generate Cyphering Block
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the message
    ct_bytes = cipher.encrypt(pad(message.encode('ascii'), 16))

    return ct_bytes


# Function takes an encrypted string and key as parameter
# and returns the decrypted version of the string.
def decryAES(message, key):
    # Generate Cyphering
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt message
    padded_message = cipher.decrypt(message)

    # Remove padding
    Encodedmessage = unpad(padded_message, 16)

    return Encodedmessage.decode('ascii')


# Description: This will take the file and decrypt it becuase it is already in
# bytes so it doesnt need to be decoded
# Parameters: The contents of the file and the key
# Return: The decrypted file data 
def decryptFile(data, key):
    # Generate Cyphering
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt message
    paddedData = cipher.decrypt(data)

    # Remove padding
    data = unpad(paddedData, 16)

    return data


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
    # enc_data = cipher_rsa_en.encrypt(message.encode('ascii'))

    enc_data = cipher_rsa_en.encrypt(message)
    f.close()

    return enc_data


# This is the RSA decrypting function, using private key.
# It takes 2 parameters: The message to be decrypted and the client name(or server) and it gets the key from the 
# required .pem file.
# It returns the decrypted message.
def decryRSA(message, client):
    filename = client + "_private.pem"
    f = open(filename, "rb")
    private_key = f.read()
    priv_key = RSA.import_key(private_key)
    cipher_rsa_dec = PKCS1_OAEP.new(priv_key)
    dec_data = cipher_rsa_dec.decrypt(message)
    f.close()
    return dec_data.decode('ascii')


def server():
    # Server port
    serverPort = 13000

    # Create server socket that uses IPv4 and TCP protocols
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:', e)
        sys.exit(1)

    # Associate 13000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:', e)
        sys.exit(1)

    # Determine the max file size
    MAX_FILE_SIZE = input("Enter the permitted file size: ")

    print('The server is ready to accept connections')

    # The server can only have one connection in its queue waiting
    # for acceptance
    serverSocket.listen(5)

    while 1:
        try:
            # Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            pid = os.fork()

            # If it is a client process
            if pid == 0:

                serverSocket.close()

                # There are only a few client names allowed.
                # Those allowed clients are kept in a list called validList.
                validList = ["client1", "client2", "client3"]

                # server receives name and check if name is valid.
                clientName = connectionSocket.recv(2048)
                clientNameDecry = decryRSA(clientName, "server")

                # split the contents of the name into name and hash
                clientNameDecryArr = clientNameDecry.split('|')
                ownHash = (hashlib.sha512(clientNameDecryArr[0].encode())).hexdigest()

                # Server computes hash itself and checks if its the same as the clients
                if (clientNameDecryArr[0] in validList) and (ownHash == clientNameDecryArr[1]):
                    connectionSocket.send("Valid".encode('ascii'))
                # The client name is not valid,
                # Appropriate message is sent to client and connection is
                # terminated
                else:
                    connectionSocket.send("Invalid clientName".encode('ascii'))
                    print("The received client", clientNameDecryArr[0], "is invalid (Connection Terminated.)")
                    connectionSocket.close()
                    return

                # Otherwise we continue with our program.
                # A 256 AES key called sym_key is generated
                # The sym_key is encrypted with the corresponding
                # client public key and sent to the client.
                KeyLen = 256
                sym_key = get_random_bytes(int(KeyLen / 8))
                sym_key_Encry = encryRSA(sym_key, clientNameDecryArr[0])


                connectionSocket.send(sym_key_Encry)
                print("Connection Accepted and Symmetric Key Generated for client:", clientNameDecryArr[0])

                # Server sends message to client, asking for file name.
                # Message is encrypted using AES.
                message = "Enter Filename:"
                messageEncry = encryAES(message, sym_key)
                connectionSocket.send(messageEncry)

                # Server receives filename.
                filenameEncry = connectionSocket.recv(2048)
                filename = decryAES(filenameEncry, sym_key)

                # split the contents of the name into file name and hash
                fileNameDecryArr = clientNameDecry.split('|')
                ownHash = (hashlib.sha512(fileNameDecryArr[0].encode())).hexdigest()

                # Server computes hash itself and checks if its the same as the clients
                if (ownHash == fileNameDecryArr[1]):
                    print("The Server recieved file name", fileNameDecryArr[0], "from client:", clientNameDecryArr[0])
                # The file name has been modified,
                # Appropriate message is sent to client and connection is
                # terminated
                else:
                    connectionSocket.send("Faulty filename".encode('ascii'))
                    print("Faulty filename (Connection Terminated).")
                    connectionSocket.close()
                    return

                # Send encrypted message to client
                reqFileSize = "Server Requested file size"
                connectionSocket.send(encryAES(reqFileSize, sym_key))

                # Receive encrypted file size from client and decode it
                encryptedFileSize = connectionSocket.recv(2048)
                fileSize = decryAES(encryptedFileSize, sym_key)

                # When the message size is larger than the limit send a message to the client and close
                # the connection, when file is not too big recieve all of it, decode it, and save it
                if (int(fileSize) > int(MAX_FILE_SIZE)):
                    # Send message that file is too big
                    fileSizeMsg = "The file size is too large.\nTerminating"
                    connectionSocket.send(encryAES(fileSizeMsg, sym_key))

                    # Close the connection and print a message
                    print("File size exceeds the threshold. Terminating connection with", clientNameDecryArr[0])
                    connectionSocket.close()
                    return
                else:
                    # Send encrypted message to client that file size if within limit
                    fileSizeMsg = "The file size is OK."
                    connectionSocket.send(encryAES(fileSizeMsg, sym_key))
                    print("Uploading data from:", clientNameDecryArr[0])

                    # Receive file data from client and decode it
                    encryptedData = connectionSocket.recv(2048)
                    encryptedHash = connectionSocket.recv(2048)

                    data = decryptFile(encryptedData, sym_key)
                    fileHash = decryAES(encryptedHash, sym_key)

                    # Server computes hash itself and checks if its the same as the clients
                    if (fileHash == (hashlib.sha512(data)).hexdigest()):
                        print("The Server recieved file", fileNameDecryArr[0], "from client:", clientNameDecryArr[0])
                    # The file has been modified,
                    # Appropriate message is sent to client and connection is
                    # terminated
                    else:
                        connectionSocket.send("Faulty file".encode('ascii'))
                        print("Faulty file (Connection Terminated).")
                        connectionSocket.close()
                        return

                    # Initilize the length of the file
                    length = len(data)

                    # Open file for writing and write the data to it
                    f = open(filename, "wb")
                    f.write(data)

                    # If there is anymore data to get collect it and write it to the file
                    while (length < int(fileSize)):
                        encryptedData = connectionSocket.recv(2048)
                        data = decryptFile(encryptedData, sym_key)
                        f.write(data)  # Write to the file
                        length += len(data)  # add to length
                    # Closes the file
                    f.close()

                    print("Upload complete from:", clientNameDecryArr[0] + ". Terminating Connection.")
                    confirmation = "The file is saved."
                    connectionSocket.send(encryAES(confirmation, sym_key))

                connectionSocket.close()

                return

            # Parent doesn't need this connection
            connectionSocket.close()

        except socket.error as e:
            print('An error occured:', e)
            serverSocket.close()
            sys.exit(1)
        except:
            print('Goodbye')
            serverSocket.close()
            sys.exit(0)


# --------------
server()
