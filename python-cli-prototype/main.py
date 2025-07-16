from time import sleep
import json
import hashlib
from treefa import get_master_key
import string
import base64

try:
    import argon2
    # from argon2
    argon2_available = True
except ImportError:
    argon2_available = False
    print("argon2 not available, using pbkdf2_hmac instead.")

SETTINGS_FILE = "settings.json"
with open(SETTINGS_FILE, "r") as f:
    settings = json.load(f)


def pos_int_input(prompt):
    while True:
        try:
            out = int(input(prompt).strip())
            if out < 0:
                print("Enter a positive integer.")
            else:
                return out
        except ValueError:
            print("Enter integer.")


def choose_option(options):
    while True:
        print("select an option:")
        for key, desc in options.items():
            print(f"[{key}] {desc}")
        choice = input("> ").strip().lower()
        if choice in options:
            return choice
        print(f"Invalid choice, please enter one of {'/'.join(options.keys())}.\n")
        sleep(0.5)

def main_menu():
    match choose_option({
        "p": "Get password",
        "c": "Change authentication methods",
        "s": "Settings",
        "q": "Quit"
    }):
        case "p":
            get_password()
        case "c":
            change_authentication_methods()
        case "s":
            change_settings()
        case "q":
            print("Exiting...")
            exit(0)



def get_password():
    master_key = get_master_key()
    
    if settings.get("saveSites", "no") == "yes":
        # print saved sites
        print("Saved sites not implemented yet.")
    

    domain = input("Enter the domain: ").strip()

    if settings.get("askUsername", "yes") == "yes":
        username = input("Enter the username: ").strip()
    else:
        username = ""
    
    if settings.get("askCounter", "yes") == "yes":
        counter = pos_int_input("Enter the password version (counter): ")
    else:
        counter = 0

    if settings.get("askPolicy", "yes") == "yes":
        policy = input("Enter the password policy: ").strip()
    else:
        policy = None

    password = generate_password(master_key, domain, username, counter, policy)
    print(f"Generated password: {password}")
    # TODO implement print/copy functionality

    # TODO save relevant data (domain, username, counter, policy) if settings allow it


def generate_password(master_key, domain: str, username="", counter=0, policy=None):
    # TODO implement policy handling (e.g., length, allowed characters)

    password_length = 16  # default password length
    allowed_chars = settings.get("allowedChars", string.ascii_letters + string.digits + string.punctuation)
    
    hash_salt = json.dumps({
        "domain": domain,
        "username": username,
        "counter": counter
    }).encode('utf-8')


    if not argon2_available:
        hashval = hashlib.pbkdf2_hmac('sha256', master_key, hash_salt, 600000, dklen=password_length)
    else:
        hashval = argon2.low_level.hash_secret_raw(master_key, hash_salt, 
                                                   time_cost=3, memory_cost=65536, parallelism=4,
                                                   hash_len=password_length, type=argon2.low_level.Type.ID)
    
    # conversion by base conversion
    x = int.from_bytes(hashval)
    password = []
    while len(password) < password_length:
        x, remainder = divmod(x, len(allowed_chars))
        password.append(allowed_chars[remainder])
    return ''.join(password)


def change_authentication_methods():
    raise NotImplementedError()
    # TODO


def change_settings():
    raise NotImplementedError()
    # TODO

if __name__ == "__main__":
    main_menu()