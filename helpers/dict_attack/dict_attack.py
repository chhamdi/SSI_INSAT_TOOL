from Crypto.Hash import MD5
import hashlib
def dict_attack():
  while True:
    dicts = [
      "names.txt",
      "dict1.txt",
      "go to previous menu: "
      ]
    print("which dictionary you want to use for the attack? :\n")
    for i in range(len(dicts)):
      if i+1 == len(dicts):
        print()
      print(f"{i+1}- {dicts[i]}")
    print()
    choice = input("type your choice please:")
    if choice not in ["1", "2", "3"]:
      print()
      print("****wrong choice!!!: \n")
    elif choice == "3":
      return
    else:
      input_hash = input("write your hash please: ")
      h = MD5.new()
      with open(f"./helpers/dict_attack/{dicts[int(choice)-1]}") as fileobj:
        for line in fileobj:
            line = line.strip()
            h.update(line.encode())
            if hashlib.md5(line.encode()).hexdigest() == input_hash:
                print ("Successfully cracked the hash ", line)
                return ""
      print ("Failed to crack the file")
      #file = open(f"./helpers/dict_attack/{dicts[int(choice)-1]}")
      #for el in file:
      #  el = el.strip()
      #  h.update(el.encode())
      #  if h.hexdigest() == input_hash:
      #    print()
      #    print ("hash has been cracked:  ", el)
      #    print()
      #    break
      #file.close()