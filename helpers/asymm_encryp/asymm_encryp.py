import getpass
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
import base64
import glob, os
import random
from math import pow

hashes = { }
rsa_key_pairs = [ ]

algos = [
    "RSA",
    "ElGamal",
    "go to previous menu: "
    ]

def gcd(a,b):
    if a<b:
        return gcd(b,a)
    elif a%b==0:
        return b
    else:
        return gcd(b,a%b)


def gen_key(q):
    key= random.randint(pow(10,20),q)
    while gcd(q,key)!=1:
        key=random.randint(pow(10,20),q)
    return key

#fonction retournant (a ^ b mod c) 
def power(a,b,c):
    x=1
    y=a
    while b>0:
        if b%2==0:
            x=(x*y)%c
        y=(y*y)%c
        b=int(b/2)
    return x%c

q=random.randint(pow(10,20),pow(10,50))
p=2*q+1
g=random.randint(2,q) #g aléatoire
a=gen_key(q) #private key
A=power(g,a,p) #public key

#Chiffrement
def encryption(msg,p,A,g):
    v=[]
    k=  (p)
    u=power(g,k,p)
    s=power(A,k,p)
    for i in range(0,len(msg)):
        v.append(msg[i])
    for i in range(0,len(v)):
        v[i]=s*ord(v[i])
    print("u = ",u)
    print("v = ",v)
    return v,u
#Déchiffrement

def decryption(v,u,a,q):
    dechiffre=[]
    h=power(u,a,q)
    for i in range(0,len(v)):
        dechiffre.append(chr(int(v[i]/h)))
    return dechiffre

q=random.randint(pow(10,20),pow(10,50))
p=2*q+1
g=random.randint(2,q) #g aléatoire
a=gen_key(q) #private key
A=power(g,a,p) #public key

for file in os.listdir(f"helpers/asymm_encryp"):
  if file.endswith(".pem"):
    rsa_key_pairs.append(file)



def key_pair_generation():
  print("keys generation :")
  passphrase = getpass.getpass("please enter a passphrase for your private key: ")
  key = RSA.generate(2048)
  while True:
    key_name = input("enter your key name: ")
    if f"{key_name}_private.pem" not in rsa_key_pairs:
      rsa_key_pairs.append(f"{key_name}_private.pem")
      rsa_key_pairs.append(f"{key_name}_public.pem")
      break
    else: 
      print("pick another name for your key please")
  private_key = key.export_key(passphrase=passphrase, pkcs=8,
                                protection="scryptAndAES128-CBC")
  file_out = open(f"./helpers/asymm_encryp/{key_name}_private.pem", "wb")
  file_out.write(private_key)
  file_out.close()
  
  public_key = key.publickey().export_key()
  file_out = open(f"./helpers/asymm_encryp/{key_name}_public.pem", "wb")
  file_out.write(public_key)
  file_out.close()

def encrypt_RSA():
  msg = str.encode(input('your message to encrypt: '))
  while True:
    key_name = input("which key you want to use: ")
    if f"{key_name}_public.pem" in rsa_key_pairs:
      break
    else:
      print("key does not exist")
      RSA_encrypt_ops()

  encoded_key = open(f"./helpers/asymm_encryp/{key_name}_public.pem", "rb").read()
  key = RSA.import_key(encoded_key)
  cipher = PKCS1_v1_5.new(key)
  ciphertext = base64.b64encode(cipher.encrypt(msg))
  print("the encrypted message is: ", ciphertext.decode())

def sign_RSA():
  message = str.encode(input('please write your message to sign: '))
  while True:
    key_name = input("which key you want to use: ")
    if f"{key_name}_private.pem" in rsa_key_pairs:
      break
    else:
      print()
      print("key does not exist!!!\n")
      print()
      RSA_encrypt_ops()
  while True:
    passphrase = getpass.getpass("please enter the passphrase of your private key: ")
    try:
      encoded_key = open(f"./helpers/asymm_encryp/{key_name}_private.pem", "rb").read()
      key = RSA.import_key(encoded_key, passphrase=passphrase)
      break
    except:
      print("wrong password, try again:")

  h = SHA256.new(message)
  signature = base64.b64encode(pkcs1_15.new(key).sign(h))
  print("here is your signed message: ", signature.decode())
  print()
  print("here's the hash used for the signature: ", h.hexdigest())
  hashes[h.hexdigest()]=h
  RSA_encrypt_ops()

rsa_e_ops = {
  "1": key_pair_generation,
  "2": encrypt_RSA,
  "3": sign_RSA
}


def decrypt_RSA():
  ciphertext=input("please write your encrypted message: ")
  ciphertext =base64.b64decode(ciphertext.encode('ascii'))
  while True:
    key_name = input("which key you want to use: ")
    if f"{key_name}_private.pem" in rsa_key_pairs:
      break
    else:
      print()
      print("key does not exist!!!\n")
      print()
      RSA_decrypt_ops()
  while True:
    passphrase = getpass.getpass("please enter the passphrase of your private key: ")
    try:
      encoded_key = open(f"./helpers/asymm_encryp/{key_name}_private.pem", "rb").read()
      key = RSA.import_key(encoded_key, passphrase=passphrase)
      break
    except:
      print("wrong password, try again:")
  cipher = PKCS1_v1_5.new(key)
  message = cipher.decrypt(ciphertext, "")
  print("message after decryption: ", message.decode())


def verify_RSA():
  while True:
    key_name = input("which key you want to use: ")
    if f"{key_name}_private.pem" in rsa_key_pairs:
      break
    else:
      print()
      print("key does not exist!!!\n")
      print()
      RSA_decrypt_ops()
  key = RSA.import_key(open(f"./helpers/asymm_encryp/{key_name}_public.pem").read())
  signature=input("write the signature to verify: ")
  signature=base64.b64decode(signature.encode('ascii'))
  used_hash=input("write the hash used for signature: ")
  try:
    pkcs1_15.new(key).verify(hashes[used_hash], signature)
    print("The signature is valid.")
  except (ValueError, TypeError):
    print("The signature is not valid.")  

rsa_d_ops = {
  "1": decrypt_RSA,
  "2": verify_RSA
}

def RSA_encrypt_ops():
  print("1-generate keys")
  print("2-encrypt with RSA")
  print("3-sign with RSA")
  print("4-go to previous menu: ")
  choice = input("Saisir votre choix ")
  print()
  if choice not in ["1", "2", "3", "4"]:
      print("****wrong choice!!!: ")
  elif choice == "4":
    return
  else:
    rsa_e_ops[choice]()

def RSA_decrypt_ops():
  print("1-decrypt a message")
  print("2-verify a signature")
  print("3-go to previous menu: ")
  choice = input("Saisir votre choix ")
  print()
  if choice not in ["1", "2", "3"]:
      print("****wrong choice!!!: ")
  elif choice == "3":
    return
  else:
    rsa_d_ops[choice]()

def ElGama_encryp():
  msg=input("write your message please:")
  print("g = ",g)
  print("public key= : ",A)
  v,u=encryption(msg,p,A,g)
  print("Message= ",msg)
  print("couple (u,v) = ","(",u,",",v,")")

def ElGama_decryp():
  print("write the (u,v) couple please:" )
  u=input("u=")
  u=int(u)
  v=input("v=")
  v=[int(s) for s in v.split(',')]
  print(v)
  dechiffre=decryption(v,u,a,p)
  d_msg=''.join(dechiffre)
  print("your message is : ",d_msg)


encrypt_choices = {
  "1": RSA_encrypt_ops,
  "2": ElGama_encryp
}

decrypt_choices = {
  "1": RSA_decrypt_ops,
  "2": ElGama_decryp
}

def encrypt_msg():
  while True:
    print("available algorithms :\n")
    for index, algo in enumerate(algos):
      print(f"{index+1}- {algo}")
    print()
    choice = input("choose your algorithm: ")
    if choice not in ["1", "2", "3"]:
      print("****wrong choice!!!: ")
    elif choice == "3":
      return
    else:
      encrypt_choices[choice]()

def decrypt_msg():
  while True:
    print("available algorithms :\n")
    for index, algo in enumerate(algos):
      print(f"{index+1}- {algo}")
    print()
    choice = input("choose your algorithm: ")
    if choice not in ["1", "2", "3"]:
      print("****wrong choice!!!: ")
    elif choice == "3":
      break
    else:
      decrypt_choices[choice]()

def asymm_encryp():
  while True:
    print("1-encrypt a message")
    print("2-decrypt a message")
    print()
    print("3-go to previous menu: ")
    choice = int(input("Saisir votre choix "))
    print()
    if choice == 1:
      encrypt_msg()
    elif choice==2:
      decrypt_msg()
    elif choice==3:
      break
    else:
      print("***wrong choice!!")
      print()
