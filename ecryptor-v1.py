import sys
import random
import secrets
import string

def core1dec(skey,ccf):
    lenskey = len(skey) - 1
    skey = bytes.fromhex(skey).decode()
    ccfs = ccf[:-(len(skey)//2)]
    ccfd = ccfs[(len(skey)//2):]
    maxindex = lenskey
    index = 0
    ccfa = bytes.fromhex(ccfd).decode()
    core1 = ''
    for e in ccfa:
        if index >= maxindex:
            index = 0
        core1 += chr(ord(e) ^ ord(skey[index]))
        index = index + 1
    return core1

def core2dec(bkey,ccs):
    lenbkey = len(bkey) - 1
    bkey = bytes.fromhex(bkey).decode()
    ccsz = ccs[:-(len(bkey)//2)]
    ccs = ccsz[(len(bkey)//2):]
    maxindex = lenbkey
    index = 0
    ccs = bytes.fromhex(ccs).decode()
    core2 = ''
    for q in ccs:
        if index >= maxindex:
            index = 0
        core2 += chr(ord(q) ^ ord(bkey[index]))
        index = index + 1
    return core2

def decrypt(key,lengthkey,ciphertext):
    lengthkey = lengthkey
    key = bytes.fromhex(key).decode()
    maxindex = len(key) - 1
    index = 0
    plaintext = ''
    ciphertext = bytes.fromhex(ciphertext).decode()
    for p in ciphertext:
        if index >= maxindex:
            index = 0
        plaintext += chr(ord(key[index]) ^ ord(p))
        index = index + 1
    return plaintext
        

def deckey(bkey,skey,enz):
    enz = bytes.fromhex(enz).decode()
    bxd = bkey[len(bkey)//2]
    sxd = skey[len(skey)//3]
    fxd = sxd + bxd
    index = 0
    key_len = ''
    keylength = 0
    maxindex = len(fxd) - 1
    for y in enz:
        if index >= maxindex:
            index = 0
        key_len += chr(ord(y) ^ ord(fxd[index]))
    keylength = int(key_len)
    return keylength
        

def key_extract(bkey,skey,enz):
    break_key = bytes.fromhex(bkey).decode()
    shield_key = bytes.fromhex(skey).decode()
    key_len = deckey(break_key,shield_key,enz)
    key = ''
    maxindex = key_len - 1
    index = 0
    for l in shield_key:
        if index >= maxindex:
            index = 0
        key += chr(ord(l) ^ ord(break_key[index]))
        index = index + 1
    return key,key_len
        
def keyend(key_size,bkey,skey):
    bx = bytes.fromhex(bkey).decode()
    sx = bytes.fromhex(skey).decode()
    bxl = bx[len(bx)//2]
    sxl = sx[len(sx)//3]
    fx = sxl+bxl
    keyenc = ''
    key_size = str(key_size)
    index = 0
    max_index = len(fx) - 1
    for t in key_size:
        if index >= max_index:
            index = 0
        keyenc += chr(ord(t) ^ ord(fx[index])).encode().hex()
        index = index + 1
    return keyenc

def core(text,skey):
    max_index = len(skey) - 1
    skey = bytes.fromhex(skey).decode()
    randomhex1 = "".join(random.choices(string.hexdigits,k=len(skey)//2))
    randomhex2 = "".join(random.choices(string.hexdigits,k=len(skey)//2))
    index = 0
    core_cipher = ''
    for l in text:
        if index >= max_index:
            index = 0
        core_cipher += chr(ord(l) ^ ord(skey[index])) 
        index = index + 1
    core_cipher = randomhex2+((core_cipher.encode()).hex())+randomhex1
    return core_cipher

def core2(text,bkey):
    max_index = len(bkey) - 1
    bkey = bytes.fromhex(bkey).decode()
    randomhex1 = "".join(random.choices(string.hexdigits,k=len(bkey)//2))
    randomhex2 = "".join(random.choices(string.hexdigits,k=len(bkey)//2))
    index = 0
    core_cipher2 = ''
    for l in text:
        if index >= max_index:
            index = 0
        core_cipher2 += chr(ord(l) ^ ord(bkey[index])) 
        index = index + 1
    core_cipher2 = randomhex2+((core_cipher2.encode()).hex())+randomhex1
    return core_cipher2

def encrypt(key,text):
    key = bytes.fromhex(key).decode()
    max_index = len(key) - 1
    index = 0
    cipher = ''
    for lt in text:
        if index >= max_index:
            index = 0
        encrypted = ord(lt) ^ ord(key[index])
        cipher += chr(encrypted)
        index = index + 1
    cipher = (cipher.encode()).hex()
    return cipher
    

def one_time(key,key_size,method):
    if method == 'e':
        keyx = ''
        pool = ''
        cpool = ''
        for i in range(0x000,0xFED):
            pool += chr(i)
        for t in range(len(key)):
            cpool += "".join(secrets.choice(pool))
        index = 0
        max_index = key_size - 1
        for l in key:
            if index >= max_index:
                index = 0
            keyx += (chr(ord(l) ^ ord(cpool[index])))
            index = index + 1
        keyx = keyx.encode().hex()
        cpool = cpool.encode().hex()
        return keyx,cpool
            
def generate_key(key_size):
    pool = ''
    pool_arr = []
    pool_arr.append("".join(random.choices(string.ascii_letters+string.digits+string.punctuation,k=key_size)))
    random_pool = ''
    key = ''
    filter_loop = key_size//4
    for rchars in range(0X000,0XFDF):
        pool += chr(rchars)
    for i in range(filter_loop):
        rpool = "".join(random.choices(pool+pool_arr[-1],k=key_size))
        pool_arr.append(rpool)
    for j in range(key_size):
        random_pool += "".join(secrets.choice(rpool))
    key = (rpool.encode()).hex()
    return key


def check():
    method = str(input("Enter The Method[Encrypt(e)/Decrypt(d)]: "))
    if method != '':
        if (method.lower()  == 'e') or (method.lower() == 'encrypt'):
            key_size = int(input("Enter The Key Size To Generate The Private Key[16,24,32,48,64]: "))
            key_size_arr = [16,24,32,48,64]
            if key_size != '':
                if key_size in key_size_arr:
                    key = generate_key(key_size)
                    skey,bkey = one_time(key,key_size,method='e')
                    keyen = keyend(key_size,bkey,skey)
                    print(f"Key: {key}")
                    print(f"ENZ Key: {keyen}")
                    print(f"Your Shield Key: {skey}")
                    print(f"Your Break Key: {bkey}")
                    text = str(input("Enter The Text To Encrypt: "))
                    if text != '':
                        cipher = encrypt(key,text)
                        print(f"The Cipher Text: {cipher}")
                        core_cipher = core(text,skey)
                        core2_cipher = core2(text,bkey)
                        print(f"CCF Text: {core_cipher}")
                        print(f"CCS Text: {core2_cipher}")
                        print(f"Key Length Composites: {len(cipher)}|{len(core_cipher)}|{len(core2_cipher)}")
                        print(f"Data Has Been Encrypted Successfully!")
                    else:
                        print("No Input Entered!")
                        sys.exit()
                else:
                    print(f"Invalid Key Size {key_size}!")
                    sys.exit()
            else:
                print("No Input Entered!")
                sys.exit()
        elif (method.lower() == 'd') or (method.lower() == 'decrypt'):
            skey = str(input("Enter Your Shield Key: "))
            skeyl = len(skey)
            if skeyl != 0:
                bkey = str(input("Enter Your Break Key: "))
                bkeyl = len(bkey)
                if bkeyl != 0:
                    enz = str(input("Enter Your ENZ Key: "))
                    if enz != '':
                        key,lengthkey = key_extract(bkey,skey,enz)
                        ciphertext = str(input("Enter Your Cipher Text: "))
                        ccf = str(input("Enter Your CCF Text: "))
                        ccs = str(input("Enter Your CCS Text: "))
                        if (ciphertext != '') and (ccf != '') and (ccs != ''):
                            plaintext =  decrypt(key,lengthkey,ciphertext)
                            core1d = core1dec(skey,ccf)
                            core2d = core2dec(bkey,ccs)
                            if (plaintext == core1d == core2d):
                                print(f"Your Plain Text: {plaintext}")
                                print(f"Data Has Been Decrypted Successfully!")
                            else:
                                print(f"Wrong Inputs Detected, Checkout Again!")
                                sys.exit()
                    else:
                        print(f"No Input Entered For ENZ Key!")
                        sys.exit()
                else:
                    print(f"No Input Entered For Break Key!")
                    sys.exit()
            else:
                print(f"No Input Entered For Shield Key!")
                sys.exit()
        else:
            print(f"No Such Method Called As {method}!")
    else:
        print("No Input Entered!")
        sys.exit()


if __name__ == '__main__':
    print("""
          ======================================================================
          =============   ENCryPt0R - V1  ---> By W.H.T.Rasanjana ==============
          ======================================================================
          (2024-09-09)
          """)
    check()