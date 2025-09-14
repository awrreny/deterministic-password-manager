from time import sleep, monotonic
import json
from auth.treefa import get_master_key, change_auth_method
import string
from collections import defaultdict
from inpututil import get_input, choose_option, RANGE_INCLUSIVE
from settings_handler import get_settings, change_settings, reset_settings
from crypto_primitives import slow_hash

try:
    import pyperclip
    clipboard_available = True
except ImportError:
    print("pyperclip not available, clipboard functionality will not work. (will print passwords instead)")
    clipboard_available = False


"""
NO SECURITY GUARANTEE
this is a python prototype - there is no guarantee of secure memory handling, input protection etc. (e.g limitations on zeroing memory after use).
Do not use this for real passwords!
"""


settings = get_settings()

if not clipboard_available:
    settings["printOrCopyPass"] = "print"  # can lead to settings file changing

POLICY_FILE = "pass_policies.json"
with open(POLICY_FILE, "r") as f:
    policies = json.load(f)

"""
there exists a removed policy which contains more characters than the default policy, but may not work with some sites.
the default policy doesn't contain potentially disallowed characters like `"`,  or ambiguous characters like `l` and `1`, `O` and `0`,
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




def main_menu():
    match choose_option({
        "p": "Get password",
        "c": "Change authentication methods",
        "s": "Change settings",
        "r": "Reset settings",
        "q": "Quit"
    }):
        case "p":
            get_password()
        case "c":
            change_authentication_methods()
            main_menu()
        case "s":
            change_settings()
            main_menu()
        case "r":
            reset_settings()
            main_menu()
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


def get_saved_data_for_domain(sites_data, domain):
    """Get the first saved data entry for a domain, or None if no data exists."""
    saved_options = sites_data.get(domain, [])
    return saved_options[0] if saved_options else None


def get_field_value(field_name, saved_data, ask_setting, prompt_func):
    """
    Get a field value, either from saved data or by asking the user.
    
    Args:
        field_name: Name of the field in saved data (e.g., 'username', 'counter', 'policy')
        saved_data: Dictionary of saved data or None
        ask_setting: Setting name to check if we should ask for this field
        prompt_func: Function to call to prompt user if no saved data
    """
    if settings.get(ask_setting, "yes") == "no":
        return None
    
    if saved_data and field_name in saved_data:
        value = saved_data[field_name]
        print(f"Autofilled {field_name}: {value}")
        return value
    else:
        return prompt_func()


def prompt_policy():
    print("\nAvailable password policies:")
    for idx, (name, policy_data) in enumerate(policies.items()):
        print(f"[{idx}] {name} ({policy_data['length']} chars)")
    
    prompt = "Enter the password policy (number) or leave blank for default\n" \
             "Tip: always picking the first applicable policy removes the need to remember which one was chosen\n> "
    
    policy_input = get_input(prompt)
    if policy_input == "":
        return policies.get("default")
    else:
        policy_num = int(policy_input)
        return list(policies.values())[policy_num]


def get_password():
    master_key = get_master_key()
    
    try:
        with open(SITE_DATA_FILE, "r") as f:
            sites_data = json.load(f)
    except FileNotFoundError:
        sites_data = {}

    if sites_data and settings.get("saveSites", "no") == "yes":
        print(f"Available sites: {', '.join(sites_data.keys())}")
    
    domain = get_input("Enter the domain\n> ")
    
    # Get saved data for this domain (if any)
    saved_data = get_saved_data_for_domain(sites_data, domain)
    if saved_data:
        print(f"Found saved data for {domain}")
    
    # Get username, counter, and policy (with autofill if available)
    username = get_field_value("username",
                                saved_data,
                                "askUsername",
                                lambda:get_input("Enter username\n> ")) or ""
    counter = get_field_value("counter", 
                              saved_data, 
                              "askCounter", 
                              lambda:get_input("Enter the password version (counter)\n> ", int, RANGE_INCLUSIVE(0))) or 0
    policy = get_field_value("policy", 
                             saved_data, 
                             "askPolicy", 
                             prompt_policy) or policies.get("default")


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
        
        hashval = slow_hash(master_key, hash_salt, password_length)

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
    change_auth_method()


if __name__ == "__main__":
    main_menu()