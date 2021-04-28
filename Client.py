import socket
import ast
from SAES import encrypt, keyExp, conv_to_hexa, conv_str_to_tuple, str2hash
from RSA import *

author_name = "Aditya Kumar Gupta"
author_roll_no = "2018013"
print("Author Name: ", author_name)
print("Author Roll No: ",  author_roll_no)
print("----------------------------------------------------------\n")


HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server


# ---------------------Input-----------------------------
message = "Secret Message"
secret_key = 1599
client_public_key_parameter = 19                        # prime number p
client_private_key_parameter = 23                       # another prime number q; q != p
# ---------------------Input End-----------------------------

print("Message:               ", message)
print("Secret Key:            ", secret_key)
print("Public Key Parameter:  ", client_public_key_parameter)
print("Private Key Parameter: ", client_private_key_parameter)

message_digest = str2hash(message)
message_digest_list = list(message_digest)

# generating public key and private key using prime no p and q;
client_public_key, client_private_key = generate_keypair(client_public_key_parameter, client_private_key_parameter)

# get client signature
client_signature = get_signature(message_digest_list, client_private_key)

keyExp(secret_key)                                      # Generate secret_keys

plaintext_list = []                                     # appending each character from message in plaintext_list
ciphertext_list = []                                    # cipher value of plaintext_list
ciphertext_list_hex = []                                # hexadecimal value of ciphertext_list
for i in range(len(message)):
    k = ord(message[i])
    plaintext_list.append(k)
    res = encrypt(k)
    ciphertext_list.append(res)
    ciphertext_list_hex.append(conv_to_hexa(res))

aes_ciphertext = "".join(x[2:] for x in ciphertext_list_hex)            # joining values of ciphertext_list_hex to show in appropriate format in terminal


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # send message to server get server public key
    s.send("send me your public key".encode())
    server_public_key = s.recv(1024)
    server_public_key = conv_str_to_tuple(server_public_key.decode('utf-8'))            # converting received value into tuple form(original form)

    # now find encrypted secret key using RSA Encryption function
    encrypted_secret_key = rsa_encrypt(server_public_key, hex(secret_key))

    print("Encrypted Secret Key:  ", conv_to_hexa(encrypted_secret_key))
    print("Ciphertext:            ", aes_ciphertext)
    print("Digest:                ", message_digest)
    print("Digital Signature:     ", conv_to_hexa(client_signature))

    # Sending Ciphertext, Encrypted Secret Key, Client Signature and Client Public Key to server 
    s.sendall(str.encode("\n".join([str(ciphertext_list), str(encrypted_secret_key), str(client_signature), str(client_public_key)])))
    data = s.recv(1024)


print('Received', repr(data))