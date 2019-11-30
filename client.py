# -------------------------------------------------------------
# Names: Bhavish Bhunjun, Erik Halabi, Dhaneshen Moonain
# Program: client.py
# -------------------------------------------------------------

import socket
import sys

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# This function takes a string as parameter.
# and returns as encrypted version of the string.
def encryAES(message, key):
    # Generate Cyphering Block
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the message
    ct_bytes = cipher.encrypt(pad(message.encode('ascii'), 16))

    return ct_bytes


def decryAES(message, key):
    # Generate ciphering
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt message
    Padded_message = cipher.decrypt(message)
    # Remove padding
    decryMessage = unpad(Padded_message, 16)

    return decryMessage.decode('ascii')


# This is the RSA encrypting function, using the public key
# It takes 2 parameters: The message to be encrypted
# and the client name(or server) and it gets the key from the 
# required .pem file.
# It returns the encoded message.
def encryRSA(message, clientName):
    filename = clientName + "_public.pem"
    f = open(filename, "rb")
    public_key = f.read()
    pubkey = RSA.import_key(public_key)
    cipher_rsa_en = PKCS1_OAEP.new(pubkey)
    enc_data = cipher_rsa_en.encrypt(message.encode('ascii'))
    f.close()

    return enc_data


# This is the RSA decrypting function, using private key.
# It takes 2 parameters: The message to be decrypted
# and the client name(or server) and it gets the key from the
# required .pem file.
# It returns the decrypted message.
def decryRSA(message, clientName):
    filename = clientName + "_private.pem"
    f = open(filename, "rb")
    private_key = f.read()
    priv_key = RSA.import_key(private_key)
    cipher_rsa_dec = PKCS1_OAEP.new(priv_key)
    dec_data = cipher_rsa_dec.decrypt(message)
    f.close()
    # return dec_data.decode('ascii')
    return dec_data


# Description: It will get a file, read it in binary, then close it
# Parameters: File name to get as string
# Return: The file contents 
def getFileSize(fileName):
    f = open(fileName, "r")
    data = f.read()
    f.close()
    length = len(data)
    return length, data


def client():
    # Ask for the nerver to connnect to
    name = input("Enter the server IP or name: ")

    # Server Information
    serverName = name
    serverPort = 13000

    # Create client socket that useing IPv4 and TCP protocols
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:', e)
        sys.exit(1)

    try:
        # Client connect with the server
        clientSocket.connect((serverName, serverPort))

        # Client receives welcome message and prompted to input name.
        # welcomeMessage = clientSocket.recv(2048)
        # print(welcomeMessage.decode('ascii'))

        # Client sends name to server
        clientName = input("Enter client name: ")
        clientNameEncry = encryRSA(clientName, "server")
        clientSocket.send(clientNameEncry)
        print("Client name", clientName, "is sent to the server.")

        # Client receives message from server.
        # If the client name is not valid, the client with get the
        # appropriate notice and connection will be terminated.
        message = clientSocket.recv(2048).decode('ascii')
        if (message == "Invalid clientName"):
            print("Invalid client name.\nTerminating.")
            clientSocket.close()
            return

        # Otherwise we continue with our program.
        # The client receives the encrypted  sym_key form the server
        # and decrypts it.
        sym_key_Encry = clientSocket.recv(2048)
        sym_key = decryRSA(sym_key_Encry, clientName)
        print("Received the symmetric key from the server.")

        # Client receives AES encrypted message from server, asking for filename.
        # Message is decrypted using sym_key.
        messageEncry = clientSocket.recv(2048)
        message = decryAES(messageEncry, sym_key)
        print(message)

        # Client inputs file name and sends to the server.
        fileName = input("")
        fileNameEncry = encryAES(fileName, sym_key)
        clientSocket.send(fileNameEncry)

        # recieve message from server
        encryptedFileSizeReq = clientSocket.recv(2048)
        fileSizeReq = decryAES(encryptedFileSizeReq, sym_key)
        print(fileSizeReq)

        # Call getFileSize function to read in the file and get the file size
        fileSize, data = getFileSize(fileName)

        # Send the file size to the server
        clientSocket.send(encryAES(str(fileSize), sym_key))

        # Get message from server on whether file is too big or not
        encryptedSizeMsg = clientSocket.recv(2048)
        sizeMsg = decryAES(encryptedSizeMsg, sym_key)
        print(sizeMsg)

        # Close the connection if the file size is too large
        if (sizeMsg == "The file size is too large.\nTerminating"):
            clientSocket.close()
            return

        # Send File to server
        print("Sending the file contents to server.")

        # Determine the number of packets
        packet = (int(fileSize) // 2048) + 1

        # Initialize the file location
        current = 0

        # While there are more packets to send keep sending the file
        # contents to the server
        while (packet != 0):
            # When we reach the last packet to send just send from current location to end
            if ((current+2048) > fileSize):
                clientSocket.sendall(encryAES(data[current:], sym_key))
            # send only 2048 bytes to the server
            else:
                # Determine the conents to send then send
                clientSocket.sendall(encryAES(data[current:current+2048], sym_key))
                # mark current file location as 1 plus 2048
                current += 2049
            # Reduce the packet number
            packet -= 1

        # Get the confirmation message and print it
        encryptedConfirmation = clientSocket.recv(2048)
        confirmation = decryAES(encryptedConfirmation, sym_key)
        print(confirmation)

        # Client terminate connection with the server
        clientSocket.close()

    except socket.error as e:
        print('An error occured:', e)
        clientSocket.close()
        sys.exit(1)


# ---------------
client()
