import random
import secrets
import math
import RSA_Keygen
import AES_CTR
import hashlib
import base64

KeySize = 16

#_______________________________
def CalculateHash(Bytes):
    Hash = hashlib.sha3_256()
    Hash.update(Bytes)
    return Hash.digest()#Return hash as bytes

#_______________________________
def MGF1(Input, Size): #Mask generation function
    Countermgf = 0
    Output = b""
    while len(Output) < Size:
        OctetString = int.to_bytes(Countermgf, 1, byteorder='big') #Transforms counter in octet string
        Output += CalculateHash(Input+ OctetString) #Concatenates the hash of the seed+Octet
        Countermgf += 1
    return Output[:Size]

#_______________________________
def OAEPC(Msg,Label=0):

    HashL = CalculateHash(int.to_bytes(Label, 256, byteorder='big'))
    Padding = ('0'*(256-len(Msg)-2*len(HashL)-2)).encode() #padding based on message and hash size
    Padding+=int.to_bytes(0x01, 1, byteorder='big')#extra byte required
    Block = HashL+Padding+Msg #Concatenation of HashL+padding

    Pass = secrets.token_bytes(len(HashL))#Local pass for masking data
    MaskedX = MGF1(Pass, 256-len(HashL)-1) #mask generated from the Pass and HashL size

    MaskedXor = int.from_bytes(Block,byteorder='big') ^ int.from_bytes(MaskedX, byteorder='big')#xor the block^1st mask
    MaskedXorBits = MaskedXor.to_bytes(256-len(HashL)-1, byteorder='big')

    MaskedPass = MGF1(MaskedXorBits, len(HashL)) #a mask is made from the pass mask
    MaskedPassXor = (int.from_bytes(Pass,byteorder='big') ^ int.from_bytes(MaskedPass, byteorder='big')).to_bytes(len(HashL), byteorder='big')
    
    #The return is a concatenation of a byte zero plus the masked hash
    return (int.to_bytes(0x00, 1, byteorder='big')+MaskedPassXor+MaskedXorBits)

#_______________________________
def OAEPD(Msg, Label=0):
    #The process is meant to reverse OAEPC
    HashL = CalculateHash(int.to_bytes(Label, 256, byteorder='big'))#Label hash is taken
    MaskedPass = Msg[1:len(HashL)+1]#the masked pass is taken from a slice of the previously generated masks
    MaskedX = Msg[len(HashL) + 1:]#the maskedX follows the same principle, but taking the other slice

    PassMask = MGF1(MaskedX, len(HashL))#A mask is generated

    Pass = int.from_bytes(MaskedPass, byteorder= 'big') ^ int.from_bytes(PassMask, byteorder='big')#mask is reverted with a xor
    PassBytes = Pass.to_bytes(len(HashL), byteorder='big')

    XMask = MGF1(PassBytes, 256-len(HashL)-1) #next mask is generated
    X = int.from_bytes(MaskedX,byteorder='big') ^ int.from_bytes(XMask, byteorder='big')#and the obfuscation is undone
    XBytes = X.to_bytes(max(1, math.ceil(X.bit_length()/8)) ,byteorder='big')
    RecoveredHash = XBytes[:len(HashL)]#and you finally get the hash as it was
    
    i = len(HashL)
    while(i < len(XBytes) and XBytes[i] == 48):
        i+=1   #Loops through bytes to check the padding signal
    
    if i == len(XBytes) or HashL != RecoveredHash: #if the hash is corrupted...
        print("Corruption on OAEP data!")
        return None
    message = XBytes[i+1:]#otherwise, it worked
    return message

#_______________________________
def Cypher(Message, e, n, SessionKey, Counter, d):

    MsgHash = CalculateHash(Message)#Take a hash of msg content and transforms in b64
    MsgHash = base64.b64encode(MsgHash)

    RSAHash = RSA_Keygen.RSAEncryption(MsgHash, e, n)#B64 hash is encrypted
    RSAHash = base64.b64encode(RSAHash)

    MsgAES = AES_CTR.Encrypt(Message, SessionKey, Counter) #Transforms msg in b64
    MsgAES = base64.b64encode(MsgAES)

    SkOAEP = OAEPC(SessionKey, d) #Session key is OAEP'd
    SkOAEP = base64.b64encode(SkOAEP)

    return RSAHash, MsgAES, SkOAEP #Return processed content to main

#_______________________________
def Decypher(Message, d, n, SessionKey, Hash, Counter):
    #data reverted from base64 encoding
    Message = base64.b64decode(Message)
    SessionKey = base64.b64decode(SessionKey)
    Hash = base64.b64decode(Hash)

    SessionKey = OAEPD(SessionKey, d) #Session Key obtained

    Hash = RSA_Keygen.RSADecryption(Hash, d, n)#Hash decrypted
    Hash = base64.b64decode(Hash) #and decoded

    Message = AES_CTR.Decrypt(Message, SessionKey, Counter)#Decryption of message

    RcvHash = CalculateHash(Message)

    if RcvHash == Hash:
        print("Hash numbers match.\nThe file has been successfully received.")
        return  Hash, SessionKey, Message
    else:
        print("Hash numbers don't match.\nThe file seems to be corrupted.")
    return

#____________________________
def main():
    Opt = input("Wish to process from file or manual input?\n(f/i): ")
    String = ' '
    if Opt == 'f':
        FileName= input("Insert filename of text to be encripted: ")
        with open(FileName, "r", encoding='utf-8') as TextFile :
            String = TextFile.read()
    else:
        String = input("Insert text to be encripted: ")

    n, e, d = RSA_Keygen.KeyGen() #takes N, private and public key
    Data = AES_CTR.TextToBytes(String)#converts input into bytes

    Opt = input("Display text as UTF-8 or bytearray?\n(u/b): ")
    
    print("________________The text to be sent is________________")
    if Opt == 'u':
        print(AES_CTR.BytesToText(Data))
    else:
        print(Data)
    print("______________________________________________________")

    #Random Key and counter for the enc/dec
    SessionKey = secrets.token_bytes(KeySize)
    Counter = secrets.token_bytes(KeySize)


    print("\n(Orig.)Hash in Base64: ", base64.b64encode(CalculateHash(Data)))
    print("\n(Orig.)Session Key in Base64: ", base64.b64encode(SessionKey))
    print("\n(Orig.)Message in Base64: ", base64.b64encode(Data))
    print("\n_______________")
    
    print("Sender encrypting info...")

    #Get the cyphered data from the function
    CypheredHash, CypheredMessage, CypheredSKey = Cypher(Data, e, n, SessionKey, Counter, d)
    print("Data encrypted.")
    print("\n(Encr.)Hash in Base64: ", CypheredHash)
    print("\n(Encr.)Session Key in Base64: ", CypheredSKey)
    print("\n(Encr.)Message in Base64: ", CypheredMessage)
    print("\n_______________")
    print("Receiver decrypting info...")
    Hs, Sk, Ms = Decypher(CypheredMessage, d, n, CypheredSKey, CypheredHash, Counter)

    print("\n(Decr.)Hash in Base64: ", base64.b64encode(Hs))
    print("\n(Decr.)Session Key in Base64: ", base64.b64encode(Sk))
    print("\n(Decr.)Message in Base64: ", base64.b64encode(Ms))
    print("\n\n")
    print("________________The text received is________________")
    if Opt == 'u':
        print(AES_CTR.BytesToText(Ms))
    else:
        print(Ms)
    print("______________________________________________________")

#_______________________________
#_______________________________
#_______________________________

main()