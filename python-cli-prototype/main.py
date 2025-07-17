from time import sleep, monotonic
import json
import hashlib
from treefa import get_master_key
import string
import base64
from collections import defaultdict

try:
    import pyperclip
    clipboard_available = True
except ImportError:
    print("pyperclip not available, clipboard functionality will not work. (will print passwords instead)")
    clipboard_available = False

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

if not clipboard_available:
    settings["printOrCopyPass"] = "print"  # can lead to settings file changing

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


# no security guarantee
def print_and_hide(message, duration):
    start = monotonic()
    try:
        while monotonic() - start < duration:
            time_remaining = round(duration - (monotonic() - start))
            m = f"\r{message} (Hidden in {time_remaining})"
            print(m, end="\r", flush=True)
            sleep(0.1)
    except KeyboardInterrupt:
        print("\033[2K\rText Hidden")
        exit(0)
    print("\033[2K\rText Hidden")


def copy_to_clipboard_and_clear(text, duration):
    pyperclip.copy(text)
    print("Copied to clipboard. Clearing in", duration, "seconds.")
    try:
        sleep(duration)
    except KeyboardInterrupt:
        print("\nClearing clipboard before exit...")
    finally:
        pyperclip.copy("")


# given a setting that is either "yes", "no" or "ask", returns True if "yes", False if "no" and asks user if "ask"
# options should be "y, n" for yes and no respectively
def get_setting_bool(setting_name, prompt, trueVal="yes", falseVal="no", trueChar="y"):
    setting_value = settings.get(setting_name, "ask")
    if setting_value == trueVal:
        return True
    elif setting_value == falseVal:
        return False
    elif setting_value == "ask":
        while True:
            return (choose_option(prompt) == trueChar)
    else:
        raise ValueError(f"Invalid setting value for {setting_name}: {setting_value}. Expected '{trueVal}', '{falseVal}' or 'ask'.")


def handle_saving(domain, username, counter, policy):
    if get_setting_bool("saveSites", {
        "y": "Save site data",
        "n": "Do not save site data"
    }):
        toSave = {}

        if get_setting_bool("saveUsernames", {
            "y": "Save username",
            "n": "Do not save username"
        }):
            toSave["username"] = username

        if get_setting_bool("saveCounters", {
            "y": "Save counter",
            "n": "Do not save counter"
        }):
            toSave["counter"] = counter

        if get_setting_bool("savePolicies", {
            "y": "Save policy",
            "n": "Do not save policy"
        }):
            toSave["policy"] = policy

        saveData(domain, toSave)


SITE_DATA_FILE = "site_data.json"
def saveData(domain, data):
    """
    Saves site data to a JSON file.
    If the file does not exist, it will be created.
    If the file exists, it will be updated with the new data.
    """
    try:
        with open(SITE_DATA_FILE, "r") as f:
            sites_data = json.load(f)
    except FileNotFoundError:
        sites_data = {}

    sites_data = defaultdict(list, sites_data)  # ensure sites_data is a defaultdict

    # Add the new data to the sites_data if not already present
    if data not in sites_data[domain]:
        sites_data[domain].append(data)
        print("Site data saved successfully.")
        with open(SITE_DATA_FILE, "w") as f:
            json.dump(sites_data, f, indent=4)
    else:
        print("Site data found (not saving again).")

    

def get_password():
    master_key = get_master_key()
    
    if settings.get("saveSites", "no") == "yes":
        with open(SITE_DATA_FILE, "r") as f:
            sites_data = json.load(f)
            print(f"Available sites: {', '.join(sites_data.keys())}")
            print("See site_data.json for saved usernames, counters, policies.")
    

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

    handle_saving(domain, username, counter, policy)

    password = generate_password(master_key, domain, username, counter, policy)

    if get_setting_bool("printOrCopyPass", {
        "p": "Print password",
        "c": "Copy password to clipboard",
    }, trueVal="print", falseVal="copy", trueChar="p"):
        print_and_hide(f"Password: {password}", settings.get("passwordShownTime", 30))
    else:
        copy_to_clipboard_and_clear(password, settings.get("passwordCopyTime", 15))




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
    # Define allowed values and types for each setting
    ALLOWED_VALUES = {
        "askUsername": (str, ("yes", "no")),
        "askCounter": (str, ("yes", "no")),
        "askPolicy": (str, ("yes", "no")),
        "printOrCopyPass": (str, ("print", "copy", "ask")),
        "saveSites": (str, ("yes", "no", "ask")),
        "saveUsernames": (str, ("yes", "no", "ask")),
        "saveCounters": (str, ("yes", "no", "ask")),
        "savePolicies": (str, ("yes", "no", "ask")),
        "passwordShownTime": (int, range(0, 121)),
        "passwordCopyTime": (int, range(0, 121)),
    }


    keys = list(settings.keys())

    # print settings
    print("Settings:")
    for idx, key in enumerate(keys):
        print(f"[{idx}] {key}: {settings[key]}")
    try:
        choice = int(input("Select a setting to change (number): "))
    except ValueError:
        print("Invalid choice.")
        return

    if 0 <= choice < len(keys):
        key = keys[choice]
        value_type, allowed_value_range = ALLOWED_VALUES[key]
        
        while True:
            new_value = input(f"Enter new value for '{key}' (current: {settings[key]}): ")
            if value_type is int:
                try:
                    new_value_int = int(new_value)
                except ValueError:
                    print("Invalid value. Please enter an integer.")
                    continue
                settings[key] = new_value_int
                if new_value_int not in allowed_value_range:
                    print(f"Invalid value. Allowed range for '{key}': {allowed_value_range}")
                else:
                    break
            elif value_type is str:
                if new_value in allowed_value_range:
                    settings[key] = new_value
                    break
                print(f"Invalid value. Allowed values for '{key}': {', '.join(allowed_value_range)}")
            else:
                raise ValueError(f"Unsupported value type {value_type.__name__}")


        with open(SETTINGS_FILE, "w") as f:
            json.dump(settings, f, indent=4)
        print("Setting updated.")
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main_menu()