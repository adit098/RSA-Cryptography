import socket
import ast
from SAES import decrypt, keyExp, conv_to_hexa, conv_str_to_tuple, str2hash
from RSA import *

author_name = "Aditya Kumar Gupta"
author_roll_no = "2018013"
print("Author Name: ", author_name)
print("Author Roll No: ",  author_roll_no)
print("----------------------------------------------------------\n")


HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

# ---------------------Input-----------------------------
server_public_key_parameter = 29                    # prime number p
server_private_key_parameter = 31                   # another prime number q
# ---------------------Input End-----------------------------


print("Public Key Parameter:  ", server_public_key_parameter)
print("Private Key Parameter: ", server_private_key_parameter)

server_public_key, server_private_key = generate_keypair(server_public_key_parameter, server_private_key_parameter)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break

            if data.decode('utf-8') == "send me your public key":
                conn.send(str(server_public_key).encode())

            else:
                ciphertext_list, encrypted_secret_key, client_signature, client_public_key = [i for i in data.decode('utf-8').split('\n')]
                ciphertext_list = ast.literal_eval(ciphertext_list)
                encrypted_secret_key = ast.literal_eval(encrypted_secret_key)
                client_signature = ast.literal_eval(client_signature)
                client_public_key = conv_str_to_tuple(client_public_key)

                secret_key = rsa_decrypt(server_private_key, encrypted_secret_key)          # get secret key using RSA Decryption function

                secret_key_value = ""
                secret_key_value = secret_key_value.join(secret_key)
                secret_key_value = int(secret_key_value, 16)                                # coverting secret_key list into int value by joining each item of list
                print("Decrypted Secret Key:  ", secret_key_value)

                keyExp(secret_key_value)                                                    # Generate keys

                plaintext_list = []
                for val in ciphertext_list:
                    plaintext_list.append(decrypt(val))

                message = ""
                for val in plaintext_list:
                    message += chr((int(val)))                                              # getting original message from cipher text by using AES decryption function

                print("Decrypted Message:     ", message)

                message_digest = str2hash(message)
                print("Message Digest:        ", message_digest)
                message_digest_list = list(message_digest)

                if verify_signature(client_signature, client_public_key, message_digest_list):          # verfying signature
                    print("Signature Verified")
                else:
                    print("Signature Not Verified")

                conn.sendall("All Processes Done Successfully".encode())
