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

"""
NO SECURITY GUARANTEE
this is a python prototype - there is no guarantee of secure memory handling, input protection etc. (e.g limitations on zeroing memory after use).
Do not use this for real passwords!
"""

SETTINGS_FILE = "settings.json"
with open(SETTINGS_FILE, "r") as f:
    settings = json.load(f)

POLICY_FILE = "pass_policies.json"
with open(POLICY_FILE, "r") as f:
    policies = json.load(f)

"""
there exists a removed policy which contains more characters than the default policy, but may not work with some sites.
the default policy doesn't contain potentially disallowed characters like `"` or `\`,  or ambiguous characters like `l` and `1`, `O` and `0`,
but still maintains >90 bits of entropy.
it was removed to make the tip 'always picking the first applicable policy' less confusing.
"allsymbols": {
        "length": 16,
        "allowedChars": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
        "requireUppercase": true,
        "requireLowercase": true,
        "requireNumbers": true,
        "requireSpecialChars": true
    },
"""


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

    policy = policies.get("default")
    if settings.get("askPolicy", "yes") == "yes":
        while True:
            # lets user choose policy by index or name
            print("\nAvailable password policies:")
            for idx, (name, ans) in enumerate(policies.items()):
                print(f"[{idx}] {name} ({ans['length']} chars)")
            ans = input("Enter the password policy or leave blank for default. " \
            "\nTip: always picking the first applicable policy removes the need to remember which one was chosen.").strip()
            if ans.isdigit() and 0 <= int(ans) < len(policies):
                policy = list(policies.values())[int(ans)]
                break
            elif ans in policies:
                policy = policies[ans]
                break
            elif ans == "":
                break
            else:
                print("Invalid policy, please enter the index or name of the policy")
                continue   

    password = generate_password(master_key, domain, username, counter, policy)
    print(f"Generated password: {password}")
    # TODO implement print/copy functionality

    # TODO save relevant data (domain, username, counter, policy) if settings allow it


def generate_password(master_key, domain: str, username, counter, policy):

    password_length = policy.get("length")
    allowed_chars = policy.get("allowedChars")
    # for rejection sampling
    policy_counter = 0


    while True:
        hash_salt = json.dumps({
            "domain": domain,
            "username": username,
            "counter": counter,
            "counter2": policy_counter,
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
        if verify_policy(policy, password):
            break

        policy_counter += 1
        if policy_counter > 100:
            raise ValueError("Failed to generate a valid password after 1000 attempts. Please check the policy settings.")
        
    return ''.join(password)


def verify_policy(policy, password):
    """
    Verifies if the password meets the policy requirements.
    Does not check length or character set as those are already enforced by the password generation.
    """
    if policy.get("requireUppercase") and not any(c.isupper() for c in password):
        return False
    
    if policy.get("requireLowercase") and not any(c.islower() for c in password):
        return False
    
    if policy.get("requireNumbers") and not any(c.isdigit() for c in password):
        return False
    
    if policy.get("requireSpecialChars") and not any(c in string.punctuation for c in password):
        return False
    
    return True


def change_authentication_methods():
    raise NotImplementedError()
    # TODO


def change_settings():
    # for now only works with string values
    ALLOWED_VALUES = {
        "askUsername": ["yes", "no"],
        "askCounter": ["yes", "no"],
        "askPolicy": ["yes", "no"],
        "printOrCopyPass": ["print", "copy", "ask"],
        "saveSites": ["yes", "no", "ask"],
        "saveUsernames": ["yes", "no", "ask"],
        "saveCounters": ["yes", "no", "ask"],
        "savePolicies": ["yes", "no", "ask"],
    }

    keys = list(settings.keys())
    print("Settings:")
    for idx, key in enumerate(keys):
        print(f"[{idx}] {key}: {settings[key]}")
    choice = int(input("Select a setting to change (number): "))
    
    if 0 <= choice < len(keys):
        key = keys[choice]
        while True:
            new_value = input(f"Enter new value for '{key}' (current: {settings[key]}): ")
            if new_value in ALLOWED_VALUES.get(key, []):
                break
            print(f"Invalid value. Allowed values for '{key}': {', '.join(ALLOWED_VALUES.get(key, []))}")
        
        settings[key] = new_value
        
        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=4)

        print("Setting updated.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main_menu()