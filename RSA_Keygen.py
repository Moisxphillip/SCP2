import random
import math

#_______________________________Changeable Configs
MillerRabinIterations = 20 #40 is usually taken as a secure number of iterations; The bigger, the better
PrimeBitLength = 1024 #Glitches if under 256 bits, only choose values higher than that
#_______________________________Global variables
Failures = 0
FailuresGCD = -1
FirstPrimes = [2,   3,   5,   7,  11,  13,  17,  19,  23,  29,
              31,  37,  41,  43,  47,  53,  59,  61,  67,  71,
              73,  79,  83,  89,  97, 101, 103, 107, 109, 113,
             127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
             179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
             233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
             283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
             353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
             419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
             467, 479, 487, 491, 499, 503, 509, 521, 523, 541]
#_______________________________Functions
def main():
    n, e, d = KeyGen() #takes N, private and public key
    print("P * Q value: " + str(n))
    print()
    print("Public Key: " + str(e))
    print()
    print("Private Key: " + str(d))
    print()

    Message  = input("Enter the message you wish to encrypt: ")
    print()

    Cypher = RSAEncryption(Message, e, n) #Encrypt
    print("Encrypted message (Hexadecimal):", end=" ")
    Data = bytearray(Cypher, "ISO-8859-1")
    print(Data.hex())
    print("\n")

    Decyphered = RSADecryption(Cypher, d, n) #Decrypt
    print("Decrypted message: " + Decyphered)
    print()

    print("Failures on prime generation: " + str(Failures))
    print("Failures on exponent generation: " + str(FailuresGCD))
    return
#_______________________________
def RSAEncryption(Message, e, n):
    MessageInBytes = bytes(Message, "ISO-8859-1") #Convert string to bytes
    BytesInInt = int.from_bytes(MessageInBytes, "big") #Convert bytes to int
    Conversion = (pow(BytesInInt, e, n))
    Output = Conversion.to_bytes((Conversion.bit_length() + 7) // 8, "big")
    return Output.decode("ISO-8859-1")

#_______________________________
def RSADecryption(Cypher, d, n):
    CypherInBytes = bytes(Cypher, "ISO-8859-1") #Convert string to bytes
    BytesInInt = int.from_bytes(CypherInBytes, "big") #Convert bytes to int
    Conversion = (pow(BytesInInt, d, n))
    Output = Conversion.to_bytes((Conversion.bit_length() + 7) // 8, "big")
    return Output.decode("ISO-8859-1")

#_______________________________
def GetPrime(n):
    global Failures #REMOVE
    while(True): #check if the obtained number is prime. If not, tries with a new one
        PossiblePrime = NBitsRandomNumber(n) #get numbers from NBitsRandomNumber
        if (DivisibleByListedPrime(PossiblePrime)): #check if divisible by first 100 primes
            if (MillerRabinTests(PossiblePrime, MillerRabinIterations)): #Check through Miller-Rabin
                return PossiblePrime #return "prime" number
        Failures = Failures + 1 #REMOVE

#_______________________________
def DivisibleByListedPrime(n):
    for i in range (0, 99):
        if ((n%FirstPrimes[i]) == 0):
            return False #Failed the test
    return True #The test was successful

#_______________________________
def MillerRabinTests(n, i):
    for i in range (0, i): #for all iterations...
        RandomForTest = random.randrange(1, n) #gets a random number for the test
        if not (MillerRabinUnit(n, RandomForTest)): #if not a prime...
            return False
    return True

#_______________________________
def MillerRabinUnit(n, a):
    Exponent = n - 1 #sets exponent below the prime we're using
    while not (Exponent & 1): #while exponent is odd
        Exponent >>= 1 #Does a shift since it's quicker than exponent // 2 and the result is the same
    if (pow(a, Exponent, n) == 1): #checks if term is divisible
        return True
    while (Exponent < n - 1): #tests next terms of the expansion
        if (pow(a, Exponent, n) == n - 1): #if the actual term is divisible
            return True
        Exponent <<= 1 #Does a shift and multiplies by 2 for the next test
    return False #the number has failed the tests

#_______________________________
def NBitsRandomNumber(n):
    # Returns an odd random number on the specified range
    return((random.randrange(2**(n-2)+1, 2**n-2) << 1 ) + 1)

#_______________________________
def KeyGen():
    global FailuresGCD #REMOVE
    p = GetPrime(PrimeBitLength)
    q = GetPrime(PrimeBitLength)
    while (p == q): #for the incredibly small chance that the generated primes are the same
        q = GetPrime(PrimeBitLength) #redo until the prime numbers are different
    n = p * q
    Totient = (p-1) * (q-1) #Takes the value of totient
    e = 0 #Initializes exponent
    GcdResult = 2 # != 1 for granting that the loop works at least on the 1st round
    while (GcdResult != 1):
        e = (random.randrange(2, Totient - 1) << 1 ) + 1 #generates odd Exponent
        if not (e > Totient): #Grants that Exponent isn't bigger than Totient
            GcdResult = math.gcd(e, Totient) #Verify if Exponent and Totient are coprimes
        FailuresGCD = FailuresGCD + 1 #REMOVE
    d = pow(e, -1, Totient) # Gets the multiplicative inverse
    return n, e, d

#_______________________________Start!
main()
