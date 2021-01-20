from Crypto.Hash import SHA256, SHA3_256, BLAKE2s, MD5
import hashlib

choices = {
  "1": SHA256.new(),
  "2": SHA3_256.new(),
  "3": BLAKE2s.new(),
}

def hash_msg():
  while True:
    hash_algos = [
      "SHA-256", 
      "SHA3-256",
      "BLAKE2s",
      "MD5",
      "go to previous menu: "
      ]
    print("liste des fonctions de hashage: \n")
    i=1
    for hash_algo in hash_algos:
      if i == len(hash_algos):
        print()
      print(f"{i}- {hash_algo}")
      i=i+1
    print()
    choice = input("choose your hash algorithm: ")
    if choice not in ["1", "2", "3", "4", "5"]:
      print("****wrong choice!!!: ")
    elif choice == "5":
      return
    elif choice =="4":
      msg_to_be_hashed = input("write the message you want to hash: ")
      print(hashlib.md5(msg_to_be_hashed.encode()).hexdigest())
    else:
      msg_to_be_hashed = input("write the message you want to hash: ")
      h = choices[choice]
      h.update(msg_to_be_hashed.encode())
      print(h.hexdigest())
      print()