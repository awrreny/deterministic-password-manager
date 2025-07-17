import json
from inpututil import get_input, RANGE_INCLUSIVE

SETTINGS_FILE = "settings.json"

def get_settings():
    with open(SETTINGS_FILE, "r") as f:
        return json.load(f)


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
        "passwordShownTime": (int, RANGE_INCLUSIVE(0)),
        "passwordCopyTime": (int, RANGE_INCLUSIVE(0)),
    }

    settings = get_settings()

    keys = list(settings.keys())

    # print settings
    print("Settings:")
    for idx, key in enumerate(keys):
        print(f"[{idx}] {key}: {settings[key]}")

    choice = get_input("Select a setting to change (number)\n> ", int, range(len(settings)))

    key = keys[choice]
    value_type, allowed_value_range = ALLOWED_VALUES[key]

    print(f"Current value: {settings[key]}")
    print(f"Allowed values: {allowed_value_range}")
    new_value = get_input(f"Enter new value for '{key}'\n> ", value_type, allowed_value_range)
    settings[key] = new_value


    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)
    print("Settings updated.")



def reset_settings():
    settings = {
        "askUsername": "yes",
        "askCounter": "yes",
        "askPolicy": "yes",
        "printOrCopyPass": "ask",
        "saveSites": "no",
        "saveUsernames": "no",
        "saveCounters": "no",
        "savePolicies": "no",
        "passwordShownTime": 30,
        "passwordCopyTime": 15,
    }
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)
    print("Settings reset to default values.")