import math
import random
import sys
import secrets

#_______________________________ Global Variables
KeyLength = 16 #Value in bytes
EncryptionRounds = 10

FwSbox = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
          0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
          0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
          0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
          0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
          0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
          0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
          0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
          0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
          0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
          0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
          0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
          0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
          0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
          0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
          0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

BytesSbox = bytearray(FwSbox)
BlockSize = 4
BlockKey = 4
ArrayWords = 44
NumberBlock = 0

#Rcon is used in KeyExpansion
Rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36]

#____________________________
def SubWord(temp): #Substitutions based on FwSbox
    toby = bytearray()
    for i in range(4):
        toby += bytearray(int.to_bytes(temp[i],4, byteorder='big'))
    return [FwSbox[i] for i in toby]#according to the FwSbox, generates a word of 4 bytes.

#____________________________
def RotWord(temp): #Rotates the word one byte to left
    return [temp[1], temp[2], temp[3], temp[0]]

#____________________________
def ColToRow(Arr): #Byte spinning for emulating the matrix operation in an array on KeyExpansion
    item = bytearray()
    k = 3
    for i in range(4): # You spin me right 'round
        k = 3-i # baby, right 'round
        for j in range(4): # Like a record, baby
            item+=int.to_bytes(Arr[k], 1, byteorder='big') # right 
            k+=4 # 'round
        k-=1 # 'round
    return item # 'round
    
#____________________________
def ByteToWord(Vec): #for conversion bytearray->wordlist on KeyExpansion
    return [int.from_bytes(Vec[0:4], byteorder='big'),
    int.from_bytes(Vec[4:8], byteorder='big'),
    int.from_bytes(Vec[8:12], byteorder='big'),
    int.from_bytes(Vec[12:16], byteorder='big')]

#____________________________
def KeyExpansion(Key):
    #[]-> [][][][][][][][][][]+[]
    roundKeys = [[0,0,0,0]]
    Key = ColToRow(Key)
    temp = ByteToWord(Key)
    for w in range(4):
        roundKeys[0][w] = temp[w]#places the matrix-spinned key in the reference position

    for i in range(EncryptionRounds+1): #Cycles of expansion start here       
        temp = roundKeys[i-1]#Key to be modified = last key
        if (i&3 == 0): #Modifies the first position as the algorithm asks for
            temp = SubWord(RotWord(temp))#Rot+Sub operations
            temp = [int.from_bytes(temp[4*k:4*(k+1)],byteorder='big') for k in range(4)]
            temp2 = bytearray(int.to_bytes(temp[0],4, byteorder='big')) #breaks word so xor Rcon can be applied on first byte
            temp3=temp2[0]^Rcon[(i)]
            temp2[0] = temp3
            temp[0] = int.from_bytes(temp2[0:4], byteorder='big')#Turns back into int

        roundKeys+= [[roundKeys[i][j-1]^temp[j] for j in range(4)]]
    return roundKeys[1:12] #Returning 11*4 bytes of fresh keys
  
#_______________________________
def BytesToMatrix(Bytes): #Conversion for the MixColumns stuff
    Matrix = []
    for i in range(16):
        if i % 4 == 0:
            Matrix.append([Bytes[i]])
        else:
            Matrix[i // 4].append(Bytes[i])
    return Matrix

#_______________________________
def MatrixToBytes(Matrix): #Conversion after finishing the MixColumns stuff
    Bytes = bytearray(16)
    for i in range(4):
        for j in range(4):
            Bytes[i*4+j] = Matrix[i][j]
    return Bytes

#_______________________________
def SubBytes(Block, Reference): #FwSbox substitutions
    Result = bytearray(16)
    for i in range(len(Block)):
        Result[i] = Reference[Block[i]]
    return Result

#_______________________________
def ShiftRows(Block):
    Result = bytearray(16) #Empty array for keeping the result
    for i in range(4):
        for j in range(4):
            Result[i*4 + j] = Block[i*4 + ((j+i)%4)] #shifts them jumping positions by index
    return Result

#_______________________________
def MultX2(Value): #
    Result = Value << 1
    Result &= 0xff
    if (Value & 128) != 0:
        Result = Result ^ 0x1b
    return Result

#_______________________________
def MultX3(Value):
    return MultX2(Value) ^ Value

#_______________________________
def SingleMix(Column):
    Result = [MultX2(Column[0]) ^ MultX3(Column[1]) ^ Column[2] ^ Column[3], #the transformation through
              MultX2(Column[1]) ^ MultX3(Column[2]) ^ Column[3] ^ Column[0],
              MultX2(Column[2]) ^ MultX3(Column[3]) ^ Column[0] ^ Column[1],
              MultX2(Column[3]) ^ MultX3(Column[0]) ^ Column[1] ^ Column[2],]
    return Result
#_______________________________
def MixColumns(Data):
    ResultMatrix = [[], [], [], []] #Empty for collecting stuff
    for i in range(4):
        Column = [Data[j][i] for j in range(4)]
        Column = SingleMix(Column)
        for i in range(4):
            ResultMatrix[i].append(Column[i]) #Prepare processed result
    return ResultMatrix

#_______________________________
def AddRoundKeys(Block, Key):
    for i in range(len(Block)):
        Block[i] = Block[i] ^ Key[i] #Xor between data and key
    return Block

#_______________________________
def XorBlocks(Data, Enc): #CTR Xor
    return bytes([Data[i] ^ Enc[i] for i in range(len(Data))])

#_______________________________
def IncreaseCtr(Counter):
    NewCtr = int.from_bytes(Counter, byteorder='big') #converts to int, increases and converts back to bytes
    NewCtr+=1
    return NewCtr.to_bytes(max(1, math.ceil(NewCtr.bit_length()/8)), byteorder='big')

#_______________________________
def BlockProcessing(Block, Key):
    for i in range(EncryptionRounds): #SubBytes->ShiftRows->MixColumns(Exceto ??ltimo round)->RoundKeys
        Block = SubBytes(Block, BytesSbox)
        Block = ShiftRows(Block)
        if not (i == EncryptionRounds - 1): #Columns aren't mixed in the final step
            Block = MatrixToBytes(MixColumns(BytesToMatrix(Block)))#Converts for operating, Mix and turn back into Bytes

        temp = bytearray()#Conversion before xor with key
        for j in range(4):
            temp+= bytearray(int.to_bytes(Key[i][j], 4, byteorder='big'))
        Block = AddRoundKeys(Block, temp)

    return Block
#_______________________________
def Encrypt(Data, Key, Counter):
    i = 0 #init index for avoiding an annoying glitch
    LocalCtr = Counter #copy of counter to be altered during process
    Result = bytearray()
    Key = KeyExpansion(Key)

    while (i < len(Data)):
        CtrEnc = bytearray(BlockProcessing(bytearray(LocalCtr), Key)) #Treats and adds processed block to encrypted file
        Result+= XorBlocks(Data[i:i+16], CtrEnc)#CTR encription happens here
        LocalCtr = IncreaseCtr(LocalCtr)

        temp = bytearray()
        for j in range(4):
            temp+= bytearray(int.to_bytes(Key[EncryptionRounds][j], 4, byteorder='big'))
        Key = KeyExpansion(temp)#converts []-> [][][][][][][][][][]+[]
        i += 16 #Skips to the next 16-bytes block
    return Result

#_______________________________
def Decrypt(Data, Key, Counter):
    i = 0 #init index for avoiding an annoying glitch
    LocalCtr = Counter #copy of counter to be altered
    Result = bytearray()
    Key = KeyExpansion(Key)

    while (i < len(Data)):
        CtrDec = bytearray(BlockProcessing(bytearray(LocalCtr), Key))
        Result+= XorBlocks(Data[i:i+16], CtrDec)
        LocalCtr = IncreaseCtr(LocalCtr)
        temp = bytearray()
        for j in range(4):
            temp+= bytearray(int.to_bytes(Key[EncryptionRounds][j], 4, byteorder='big'))
        Key = KeyExpansion(temp)
        i += 16 #Skips to the next 16-bytes block
    return Result

#_______________________________
def Padding(Bytes):
    NeededPadding = 0x10 -(len(Bytes) % 0x10) #Calculates padding based on byte length % block size in bytes
    return Bytes + bytes([NeededPadding] * NeededPadding)

#_______________________________
def Unpadding(Bytes):
    PaddingDone = Bytes[len(Bytes) - 1]
    Bytes = Bytes[:-PaddingDone] #Cuts a distance of bytes at the end equivalent to the padding size
    return Bytes

#_______________________________
def TextToBytes(Text):
    Bytes = bytes(Text, "ISO-8859-1") #Turns text into byte array
    Bytes = Padding(Bytes) #does padding for encription integrity
    return Bytes
#_______________________________
def FileToBytes(Name):
    Bytes = bytes(Name, "ISO-8859-1") #TODO load as file
    Bytes = Padding(Bytes) #does padding for encription integrity
    return Bytes
#_______________________________
def BytesToText(Bytes):
    Bytes = Unpadding(Bytes) #undoes padding for recovering text integrity
    Text = Bytes.decode("ISO-8859-1") #Bytes are interpreted as text again
    return Text
#_______________________________
def BytesToFile(Bytes):
    Bytes = Unpadding(Bytes) #undoes padding for recovering text integrity
    File = Bytes.decode("ISO-8859-1") #TODO load as file
    return File

#_______________________________________________________________Start!
#main()



#_______________________________________________________________________________________________
