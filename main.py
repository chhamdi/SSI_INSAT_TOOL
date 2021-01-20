from helpers.encode_decode.encode_decode import encode_decode
from helpers.hash_msg.hash_msg import hash_msg
from helpers.dict_attack.dict_attack import dict_attack
from helpers.main_menu.main_menu import show_menu, show_title
from helpers.symm_encryp.symm_encryp import symm_encryp
from helpers.asymm_encryp.asymm_encryp import asymm_encryp

choices = {
  "1":  encode_decode,
  "2":  hash_msg,
  "3":  dict_attack,
  "4":  symm_encryp,
  "5":  asymm_encryp
}

show_title()
while True:
  show_menu()
  choice = input("choose your option: ")
  if choice not in ["1", "2", "3", "4", "5", "6"]:
    print("***wrong choice: ")
  elif choice == 6:
    break
  else:
    choices[choice]()