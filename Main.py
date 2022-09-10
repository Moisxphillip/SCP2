import random
import secrets
import math
import RSA_Keygen
import AES_CTR

KeySize = 16

def RSACypher():
    SessionKey = secrets.token_bytes(KeySize)



def main():
    n, e, d = RSA_Keygen.KeyGen() #takes N, private and public key
    print("Public Key: " + str(e))
    print()
    print("Private Key: " + str(d))
    print()

    #Nonce = secrets.token_bytes(KeySize)

    Message  = input("Enter the message you wish to encrypt: ")
    print()

    Cypher = RSA_Keygen.RSAEncryption(Message, e, n) #Encrypt
    print("Encrypted message (Hexadecimal):", end=" ")
    Data = bytearray(Cypher, "ISO-8859-1")
    print(Data.hex())
    print("\n")

    Decyphered = RSA_Keygen.RSADecryption(Cypher, d, n) #Decrypt
    print("Decrypted message: " + Decyphered)
    print()
    
    return

main()