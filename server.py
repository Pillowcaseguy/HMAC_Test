#!/usr/bin/env python3
import socket
import struct
import time
import hmac
import hashlib
import base64

# Configure the server to listen on all interfaces and a specified port.
HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 5001  # Port to listen on

#Neville Pochara's attempt at sending and receiving a juicy HMAC message and key. Then verifying it.

class testing_HMAC:
    def __init__(self,key):
        self.secret_key = key
        self.encoded_hmac = None

    def compute_hmac(self,message): # This computes our hmac. It also sets our internal encoded_hmac value for use.
        # Choose a hash function
        hash_algorithm = hashlib.sha256
        # Compute the HMAC using the chosen hash function and the secret key
        hmac_object = hmac.new(self.secret_key.encode(), message, hash_algorithm)
        # Get the digest (HMAC value)
        hmac_digest = hmac_object.digest()
        # Encode the digest to Base64 or hexadecimal
        encoded_hmac = base64.b64encode(hmac_digest).decode()  # Base64 encoding
        self.encoded_hmac = encoded_hmac

    def verify_message(self,message,sent_hmac): #message: The user message. sent_hmac: The user's generated hmac.
        #This is the website receiving the user message + their hmac, and comparing it with our own!
        theMessage = message.encode()
        if not self.encoded_hmac:
            print("No encoded HMAC value built yet. Please run compute_hmac().")
            return
        else:
            test_hmac = hmac.new(self.secret_key.encode(),theMessage,hashlib.sha256).digest() #Key, message, then the algorithm (hashlib.sha256)
            test_hmac = base64.b64encode(test_hmac).decode() #Encode then decode

            if hmac.compare_digest(test_hmac,sent_hmac.decode()): #User's hmac + our own computed one match
                #Allegedly, doing == is opening our program up to a timing attack. I learned something new today!
                #print("Message Verification Successful.")
                return True
            else: #If it was tampered with we fail.
                #print("THE MESSAGE OR SOMETHING WAS TAMPERED WITH ALERT\nMessage Verification Failed.")
                return False

    def return_encoded_hmac(self):
        if not self.encoded_hmac:
            print("No encoded hmac value built yet. Please run compute_hmac().")
        else:
            return self.encoded_hmac

def process_received_data(data):
    # Assuming the data is formatted as "<hmac>|<message>"
    hmac_hash, message = data.split(b"|", 1)  # Split the data at the delimiter
    return hmac_hash, message  # Return the HMAC and the message as byte strings

# Example usage
"""message = "Hello, HMAC!"
secret_key = "mySecretKey"

Hmac = testing_HMAC(secret_key)
Hmac.compute_hmac(message)

print("HMAC:")
print(Hmac.return_encoded_hmac())
print()
Hmac.verify_message(message,Hmac.return_encoded_hmac())"""

the_key = "abcdf"

HmacAndCheese = testing_HMAC(the_key)

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}")

        conn, addr = server_socket.accept()
        with conn:
            print('Connected by', addr)
            total_received = 0
            conn.send(HmacAndCheese.secret_key.encode("utf-8")) #Transmitting our juicy secret key once

            start_time = time.time()

            # Keep reading data until the client signals EOF (empty read)
            while True:
                length = conn.recv(4) #Receiving 4 bytes of an integer for message size
                if not length:
                    break
                message_length = struct.unpack('!I', length)[0]

                message = conn.recv(message_length)  #Hope this works; message length ensures we get the correct size of the message
                if not message:
                    break
                total_received += len(message)

                hmac_hash, message = process_received_data(message)
                print(f"Received HMAC: {hmac_hash.decode()}")
                #print(f"Received message: {message}")

                HmacAndCheese.compute_hmac(message)
                print(f"Computed HMAC: {HmacAndCheese.return_encoded_hmac()}")
                if HmacAndCheese.verify_message(message.decode(),hmac_hash):
                    print("Message verified.")
                else:
                    print("MESSAGE IS BAD")
                    break

            end_time = time.time()
            elapsed = end_time - start_time
            throughput = total_received / elapsed if elapsed > 0 else 0

            print(f"Received {total_received} bytes in {elapsed:.2f} seconds.")
            print(f"Throughput: {throughput / 1024:.2f} KB/s")

            # Send an acknowledgment back to the client
            conn.sendall(b"ACK")


if __name__ == "__main__":
    start_server()
