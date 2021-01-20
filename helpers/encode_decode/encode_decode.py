import base64

def encode_msg():
  msg = input("write the message to encode: ")
  base64_bytes = base64.b64encode(msg.encode('ascii'))
  print("your encoded message is: ",base64_bytes)

def decode_msg():
  msg = input("write the message to decode: ")
  sample_string_bytes =base64.b64decode(msg.encode('ascii'))
  sample_string = sample_string_bytes.decode("ascii") 
  print("Le message original est: ",sample_string)


choices = {
  "1":  encode_msg,
  "2":  decode_msg  
}
def encode_decode():
  while True:
    print("---------------------------------------------------\n")
    print("1- encode a message:")
    print("2- decode a message:")
    print("3- go to previous menu:")
    print("---------------------------------------------------\n")
    choice = input("choose your option: ")
    if choice not in ["1", "2", "3"]:
      print("wrong choice: ")
    elif choice == "3":
      return
    else:
      choices[choice]()

