# -*- coding: utf-8 -*-
import ecdsa
import ecdsa.der
import ecdsa.util
import binascii
import os
import hashlib
import random

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def countLeadingChars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count
    
def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n /= 58
    return result

    
def base58decode(s):
    result = 0
    for i in range(0, len(s)):
        result = result * 58 + b58.index(s[i])
    return result

    
def base256encode(n):
    result = ''
    while n > 0:
        result = chr(n % 256) + result
        n /= 256
    return result

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
    return result

    


def base58CheckEncode(version, payload):
    s = chr(version) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leadingZeros = countLeadingChars(result, '\0')
    return '1' * leadingZeros + base58encode(base256decode(result))

    
def base58CheckDecode(s):
    leadingOnes = countLeadingChars(s, '1')
    s = base256encode(base58decode(s))
    result = '\0' * leadingOnes + s[:-4]
    chk = s[-4:]
    checksum = hashlib.sha256(hashlib.sha256(result).digest()).digest()[0:4]
    assert(chk == checksum)
    version = result[0]
    return result[1:]
    
    
def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')

    
def privateKeyToWif(key_hex):    
    return base58CheckEncode(0x80, key_hex.decode('hex'))
    
 
def wifToPrivateKey(s):
    b = base58CheckDecode(s)
    return b.encode('hex')    

def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return base58CheckEncode(0, ripemd160.digest())

    
if __name__ == "__main__":
    import time
    import re
    import sys
    from multiprocessing import Pool

    
    key = re.compile("^1" + str(sys.argv[1]))
 
    def run():
        while 1:
            private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
            address = keyToAddr(private_key)
            wif = privateKeyToWif(private_key)
            a = re.search(key, address)
            if a:
                want = "[WANT]" + "\n" + private_key + "\n" +address + "\n" + wif + "\n"
                print want
                os.system("echo [WANT]%s, %s, %s > bitcoin_miner_want.txt" % (address, private_key, wif))
            else:
                temp = "[TMP]" + "\n" + private_key + "\n" + address + "\n" + wif + "\n"
                os.system("echo [temp]%s, %s , %s >> bitcoin_miner_tmp.txt" % (address, private_key, wif))
     
    p = Pool()
    for i in range(3):
        p.apply_async(run)
    p.close()
    p.join()
