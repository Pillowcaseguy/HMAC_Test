#!/usr/bin/env python3
import socket
import struct
import time
import random
import hmac
import hashlib
import base64

#Neville Pochara's attempt at smelling a server and sending data to it, with message + hash

# Set the server address and port (adjust if running on a different machine)
HOST = '127.0.0.1'  # Server IP address
PORT = 5001  # Server port

class testing_HMAC:
    def __init__(self,key):
        self.secret_key = key
        self.encoded_hmac = None

    def compute_hmac(self,message): # This computes our hmac. It also sets our internal encoded_hmac value for use.
        # Choose a hash function
        hash_algorithm = hashlib.sha256
        # Compute the HMAC using the chosen hash function and the secret key
        hmac_object = hmac.new(self.secret_key, message.encode(), hash_algorithm)
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
            test_hmac = hmac.new(self.secret_key,theMessage,hashlib.sha256).digest() #Key, message, then the algorithm (hashlib.sha256)
            test_hmac = base64.b64encode(test_hmac).decode() #Encode then decode
            print(test_hmac)

            if hmac.compare_digest(test_hmac,sent_hmac): #User's hmac + our own computed one match
                #Allegedly, doing == is opening our program up to a timing attack. I learned something new today!
                print("Message Verification Successful.")
                return True
            else: #If it was tampered with we fail.
                print("THE MESSAGE OR SOMETHING WAS TAMPERED WITH ALERT\nMessage Verification Failed.")
                return False

    def return_encoded_hmac(self):
        if not self.encoded_hmac:
            print("No encoded hmac value built yet. Please run compute_hmac().")
        else:
            return self.encoded_hmac

def run_client():
    # Benchmark settings:
    message_size = 1024 * 1024  # 1 MB per message
    num_messages = 100  # Total of 10 messages
    total_bytes = message_size * num_messages

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        print(f"Connected to server at {HOST}:{PORT}")

        juicy_key = client_socket.recv(256) #The server is expected to send the key once.
        print("A Yummy Juicy Key Was Received!")

        Hmac = testing_HMAC(juicy_key)

        # Start timer for the benchmark
        start_time = time.time()

        # Send the data in a loop
        for i in range(num_messages):
            random_char = chr(random.randint(32, 123))  # A character between 32-123 is a valid ASCII character (excluding |)
            data = random_char * message_size  # Create a 1 MB block of data
            Hmac.compute_hmac(data) #We compute the HMAC using the byte + key
            x = Hmac.return_encoded_hmac() #We store then send the computed HMAC and the message

            message_length = len(f"{x}|{data}")
            client_socket.sendall(struct.pack('!I', message_length))
            message_with_hmac = f"{x}|{data}"  # Separate HMAC and message with a delimiter (hope this works)
            client_socket.sendall(message_with_hmac.encode())

            print("Message sent (partial): ", data[0:10])
            print(f"Sent message {i + 1}/{num_messages}")

        # Shutdown the sending side to indicate completion
        client_socket.shutdown(socket.SHUT_WR)

        # Optionally, wait for an acknowledgment from the server
        ack = client_socket.recv(1024)
        print("Received acknowledgment:", ack.decode())

        end_time = time.time()
        elapsed = end_time - start_time
        throughput = total_bytes / elapsed if elapsed > 0 else 0

        print(f"Sent {total_bytes} bytes in {elapsed:.2f} seconds.")
        print(f"Throughput: {throughput / 1024:.2f} KB/s")


if __name__ == "__main__":
    run_client()
