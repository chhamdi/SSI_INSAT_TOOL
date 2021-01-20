

import json
from base64 import b64encode,b64decode
from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
import getpass

algos = [
    "AES", 
    "DES3",
    "go to previous menu: "
    ]
encrypted_data = { }
session = { }

def encrypt_AES():
  if "AES_key" not in session.keys():
    key = get_random_bytes(16)
    session["AES_key"] = key
  msg_to_encrypt = input("enter the message you want to encrypt: ")
  cipher = AES.new(session["AES_key"], AES.MODE_CFB)
  ct_bytes = cipher.encrypt(msg_to_encrypt.encode())
  iv = b64encode(cipher.iv).decode('utf-8')
  ct = b64encode(ct_bytes).decode('utf-8')
  encrypted_data[ct] = iv
  print("encrypted message: ", ct)
  print("initialization vector message: ", iv)

def decrypt_AES():
  ct = input("enter a message to decrypt: ")
  iv= b64decode(encrypted_data[ct])
  ct = b64decode(ct)
  cipher = AES.new(session["AES_key"], AES.MODE_CFB, iv=iv)
  pt = cipher.decrypt(ct)
  print("The message was: ", pt.decode())

def encrypt_DES3():
  if "DES3_key" not in session.keys():
    key = DES3.adjust_key_parity(get_random_bytes(24))
    session["DES3_key"] = key
  msg_to_encrypt = input("enter the message you want to encrypt: ")
  cipher = DES3.new(session["DES3_key"], DES3.MODE_CFB)
  iv = b64encode(cipher.iv).decode('utf-8')
  ct_bytes = cipher.encrypt(msg_to_encrypt.encode())
  ct = b64encode(ct_bytes).decode('utf-8')
  encrypted_data[ct] = iv
  print("encrypted message: ", ct)
  print("initialization vector message: ", iv)

def decrypt_DES3():
  ct = input("enter a message to decrypt: ")
  iv= b64decode(encrypted_data[ct])
  ct = b64decode(ct)
  cipher = DES3.new(session["DES3_key"], DES3.MODE_CFB, iv=iv)
  pt = cipher.decrypt(ct)
  print("The message was: ", pt.decode())

encrypt_choices = {
  "1": encrypt_AES,
  "2": encrypt_DES3
}

decrypt_choices = {
  "1": decrypt_AES,
  "2": decrypt_DES3
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
      break
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

def symm_encryp():
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
