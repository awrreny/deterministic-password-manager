# Deterministic Password Manager

A cryptographically secure, deterministic password generation system that eliminates storage requirements while enabling flexible, rule-based password recovery through recursive Shamir's Secret Sharing.

## Why Deterministic Over Traditional Encryption?

### Problems with Traditional Password Managers

Traditional password managers store encrypted passwords, either locally or on the cloud, and when a password is needed, the user supplies a master password and decrypts the stored password.

Asking for the master password each time ensures that no private information is stored anywhere, which is a key property of password managers.

This model works well and is the main variant of password manager, but it does face some challenges:

1. **Storage Dependency**: Encrypted password vaults must be stored somewhere (cloud, local files), creating single points of failure
2. **Synchronization Complexity**: Multi-device access requires sync mechanisms that require an internet connection and account/authentication logic
3. **Attack Surface**: Encrypted databases are attractive targets for offline attacks

### The Deterministic Approach

Deterministic password managers address these issues by generating each password on request, instead of storing them. It uses a deterministic function (e.g hash function) with a master password and a site identifier so that regardless of the device, if the same master password and site identifier is entered, the same password is generated.

While this removes the requirements for cloud synchronisation and password storage, it comes with some tradeoffs:

1. **Recovery Limitations**: Master password loss means complete data loss
2. **Inflexible Passwords**: Password changes and sites with unconventional password rules are hard to deal with and may require extra parameters (e.g counter or policy) that would need to be remembered, stored, or found with trial-and-error on each request
3. **Account Compromise**: If master password is compromised, all accounts are compromised. In a traditional password manager, both the master password and the encrypted password vault must be compromised to put accounts at risk.

### Deterministic Password Manager with Secret Sharing

This project attempts to remedy the recovery limitations by using Shamir's Secret Sharing to simulate the standard recovery methods of online accounts, such as recovery codes.

Secret Sharing is a cryptographic primitive that allows a secret (e.g the master password) to be split into multiple shares in a way that only certain combinations of shares can reconstruct the original secret. For example, a "3-of-5" scheme would split the master password into 5 shares, and any 3 of those shares can be used to reconstruct the master password. This allows for flexible authentication rules, such as "any 2 of (work_password, personal_password, recovery_password)"

It is also possible to recursively use secret sharing on the shares themselves to allow nested tree-based logic for complex recovery rules like "executive_password or any 2 of employee_passwords", where both `or` and `any` are uses of secret sharing.

To make this user-friendly, a parser is implemented to convert rules like the above from nearly natural language into the necessary secret sharing structures.

Unfortunately, the secret sharing structures require local storage, which forfeits the easy cross-device use, but the data transfer only needs to be done once during setup, and the data is not sensitive (it does not contain passwords or any private information), so it can be easily transferred between devices. An alternative is to create the structures identically on each device, which is possible as the process is deterministic.

Also, this does not solve the problem of inflexible passwords, so a counter and password policy storage is still required. I tried to make this more user friendly by _optionally_ allowing per-site policies and counter values to be stored in a local file. Note that this file is not yet encrypted so the list of sites may be known by anyone with access to the data.

<!-- note for future: can have mechanism that allows a raw, easily-rememberable password to authenticate with 0 storage by doing: password -> hash
but then create treefa tree top-down by splitting the hash
still requires storage for the treefa tree in the password nodes
but allows the option of using the main master password with 0 storage
(for easy multi-device access)

it seems to not be possible to create a reversed secret sharing scheme where a secret is generated from shares rather than the other way around
if it was possible then it would be possible to do treefa with 0 storage (but not with the above way) -->

## Features

-   **No Password Storage**: Passwords derived on-demand from master key and site identifier
-   **Natural Language Rules**: Define authentication like "executive_password or any 2 of employee_passwords"
-   **Simple Multi-device Use**: Either transfer treefa_tree.pkl or create it identically on each device
-   **Custom Cryptography**: Implementations of Shamir's Secret Sharing, binary extension fields, and Lagrange interpolation, all built from scratch without external libraries

## Implementation Details

### Secret Salting

One notable property of Shamir's Secret Sharing is that once you know t shares, you can reconstruct the other n-t shares. This is a problem if you use the same password in different parts of the tree, e.g in '(a or b) and a', where 'a' is used twice. If an attacker knows 'b', they can reconstruct both shares of 'a' and thus the master password. (There are non-trivial examples of this problem in more complex trees)

This is solved by salting and hashing each share, where the salt is derived (deterministically) from the rest of the shares in the tree (and the threshold number). This means that even if the same password is used in different parts of the tree, the actual share value will be different due to the different salts.

### UI

The CLI at `main.py` is the primary program, but there exists a simple Tkinter GUI at `run_gui.py` that can be used to generate passwords. It is not as fully-featured as the CLI, but it is easier to use for simple password generation.

---

_Prototype only - not for production use_
