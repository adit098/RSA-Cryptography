import hashlib

author_name = "Aditya Kumar Gupta"
author_roll_no = "2018013"


def str2hash(msg):
    result = hashlib.md5(msg.encode())
    return result.hexdigest()

    
# S-Box
sBox  = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]

# Inverse S-Box
sBoxI = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
         0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]

# Round keys: K0 = w0 + w1; K1 = w2 + w3; K2 = w4 + w5
w = [None] * 6

def mult(p1, p2):
    """Multiply two polynomials in GF(2^4)/x^4 + x + 1"""
    p = 0
    while p2:
        if p2 & 0b1:
            p ^= p1
        p1 <<= 1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111

# Forming 2x2 matrix from 16 bit value
def intToVec(n):
    """Convert a 2-byte integer into a 4-element vector"""
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]            

# Getting 16 bit value from the converted 2x2 matrix
def vecToInt(m):
    """Convert a 4-element vector into 2-byte integer"""
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]

# Add Round Key
def addKey(s1, s2):
    """Add two keys in GF(2^4)"""   
    return [i ^ j for i, j in zip(s1, s2)]

# Substitute Nibbles
def sub4NibList(sbox, s):
    """Nibble substitution function"""
    return [sbox[e] for e in s]

# Shift Row
def shiftRow(s):
    """ShiftRow function"""
    return [s[0], s[1], s[3], s[2]]

# Expand Key
def keyExp(key):
    """Generate the three round keys"""
    def sub2Nib(b):
        """Swap each nibble and substitute it using sBox"""
        return (sBox[(b >> 4)] << 4) + sBox[b & 0x0f]

    def rot2Nib(b):
        return ((b<<4)&0x00f0) + ((b>>4)&0x000f)

    Rcon1, Rcon2 = 0b10000000, 0b00110000
    w[0] = (key & 0xff00) >> 8
    w[1] = key & 0x00ff
    w[2] = w[0] ^ Rcon1 ^ sub2Nib(rot2Nib(w[1]))
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ Rcon2 ^ sub2Nib(rot2Nib(w[3]))
    w[5] = w[4] ^ w[3]


def conv_to_hexa(s):                        # convert to hexadecimal
	if type(s) == int:
		return hex(s)

	else:
		ls = ""
		for i in s:
			ls+=hex(i)[2:]
		return '0x'+ ls[0] + ls[2] + ls[1] + ls[3]


def conv_str_to_tuple(key_str):
    key_str = key_str[1:len(key_str)-1]
    key_tuple = tuple(map(int, key_str.split(', ')))
    return key_tuple


# Encryption
def encrypt(ptext):
    """Encrypt plaintext block"""
    def mixCol(s):
        return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]),
                s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]    
    
          
    state = intToVec(((w[0] << 8) + w[1]) ^ ptext)                          # Add Round 0 Key

    ## -----------Round1 Start----------
    state = sub4NibList(sBox, state)                                        # Substitute nibbles
    state = shiftRow(state)                                                 # Shift rows
    state = mixCol(state)                                                   # Mix columns
    state = addKey(intToVec((w[2] << 8) + w[3]), state)                     # Add Round 1 Key
    ## -----------Round1 End----------


    ## ------------Round2 Start---------
    state = sub4NibList(sBox, state)                                        # Substitute nibbles
    state = shiftRow(state)                                                 # Shift rows
    state = vecToInt(addKey(intToVec((w[4] << 8) + w[5]), state))           # Add Round 2 Key
    ## ----------Round2 End---------

    return state                                                           ## Returned Encrypted value
   

# Decryption
def decrypt(ctext):
    """Decrypt ciphertext block"""
    def iMixCol(s):
        return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]),
                mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]
    
    
    state = intToVec(((w[4] << 8) + w[5]) ^ ctext)                          # Add Round 2 Key


    ## ------------Round1 Inverse Start---------------
    state = shiftRow(state)                                                 # Inverse Shift Row
    state = sub4NibList(sBoxI, state)                                       # Inverse Nibble Sub
    state = addKey(intToVec((w[2] << 8) + w[3]), state)                     # Add Round 1 Key

    state = iMixCol(state)                                                  # Inverse Mix Columns
    ## ------------Round1 Inverse End-----------------

    ## ------------Round2 Inverse Start---------------
    state = shiftRow(state)                                                 # Inverse Shift Row
    state = sub4NibList(sBoxI, state)                                       # Inverse Nibble Sub
    state =  vecToInt(addKey(intToVec((w[0] << 8) + w[1]), state))          # Add Round 0 Key       
    ## ------------Round2 Inverse End-----------------

    return state                                                            ## Returned Decrypted value