# 'tree-factor authentication'
# zero-knowledge tree thing that only gives the 'root secret' if all conditions are met
# this zero-knowledge is enforced cryptographically rather than by a server
# e.g for local password managers

# TODO add OrNode and AndNode as wrappers for AnyTNode with t=1 and t=n 
import pickle
from dataclasses import dataclass
from inpututil import get_input, choose_option
from crypto_primitives import slow_hash, fast_hash, NoLeakSecretSharer
from getpass import getpass

TREE_FILE = "treefa_tree.pkl"

@dataclass(frozen=True)
class AuthNode:
    verification_hash: bytes
    name: str


@dataclass(frozen=True)
class PasswordNode(AuthNode):
    pass


@dataclass(frozen=True)
class AnyTNode(AuthNode):
    threshold: int
    children: list[AuthNode]
    sharer_object: NoLeakSecretSharer

    
def testnode(pwd):
    return PasswordNode(fast_hash(slow_hash(pwd.encode())), f"password is {pwd}")


def create_anyt_node(children, threshold, name):
    # temporary, should cache to make easier?
    shares = [
        get_node_secret(child)
        for child in children
    ]
    sharer = NoLeakSecretSharer(shares, threshold)
    secret = sharer.get_secret({
        i: share
        for i, share in enumerate(shares)
    })
    return AnyTNode(verification_hash=fast_hash(secret),
                    name=name,
                    threshold=threshold,
                    children=children,
                    sharer_object=sharer)


def get_node_secret(node: AuthNode):
    match node:
        case PasswordNode(verification_hash=verification_hash, name=name):
            while True:
                password = getpass(f"Enter password for node {name} (input will be hidden):\n> ")
                # there are 2 hashes here - the first is more of an encoding or an extending
                # the 2nd is to check if the correct password was entered, but is only for usability (to notify user if password is wrong)
                # it has no cryptographic role in terms of getting the node secret (or any other secret)
                secret = slow_hash(password.encode())
                if fast_hash(secret) == verification_hash:
                    return secret
                else:
                    print("Incorrect password")


        case AnyTNode(verification_hash=verification_hash, threshold=threshold, children=children, sharer_object=sharer_object, name=name):
            known_shares = dict()
            auth_options = {
                i: child.name
                for (i, child) in enumerate(children)
            }
            while threshold > 0:
                node_index = choose_option(auth_options,
                                            text1=f"Select which method to authenticate with. ({threshold} remaining)",
                                            inp_type=int, # type: ignore
                                            )
                known_shares[node_index] = get_node_secret(children[node_index])
                auth_options.pop(node_index)
                threshold -= 1

            secret = sharer_object.get_secret(known_shares)

            if fast_hash(secret) != verification_hash:
                raise ValueError(f"Node '{name}' failed verification")
            
            return secret
        
        case _:
            raise NotImplementedError()


def create_tree_and_return_secret() -> tuple[AuthNode, bytes]:
    node_types = {
        "p": "Password Node",
        "t": "Threshold Node (authenticate any t of its children)"
    }
    match choose_option(node_types):
        case "p":
            node_name = get_input("Enter name for this node:\n> ")
            while True:
                password = getpass("Enter password (input will be hidden):\n> ")
                confirm_pass = getpass("Enter again:\n> ")
                if password == confirm_pass: break
                print("Passwords didn't match")
            secret = slow_hash(password.encode())
            verification_hash = fast_hash(secret)
            return PasswordNode(verification_hash, node_name), secret
        
        case "t":
            node_name = get_input("Enter name for this node:\n> ")
            # currently have n children
            # add more or finish?
            # prevent empty list (and singleton?)
            children: list[AuthNode] = []
            shares: list[bytes] = []
            while True:
                print(f"Adding child {len(children)+1} of {node_name}:")
                child, share = create_tree_and_return_secret()
                children.append(child)
                shares.append(share)

                if len(children) >= 2 and choose_option({
                    "a": "Add another child node",
                    "f": "Finished adding children"
                }) == "f":
                    break
            print("Child nodes: ")
            print("\n".join(child.name for child in children))
            threshold = get_input(f"Enter threshold number of child nodes to verify this node. " \
                                  f"e.g enter 1 to require any child node, or {len(children)} to require all:\n> ",
                                  int, range(1, len(children)+1)) # type: ignore

            sharer = NoLeakSecretSharer(shares, threshold)
            secret = sharer.get_secret({
                i: share
                for i, share in enumerate(shares)
            })
            return AnyTNode(verification_hash=fast_hash(secret),
                            name=node_name,
                            threshold=threshold,
                            children=children,
                            sharer_object=sharer), secret
        case _:
            raise ValueError
        

def save_tree(obj):
    with open(TREE_FILE, 'wb') as f:
        pickle.dump(obj, f)


def load_tree():
    with open(TREE_FILE, 'rb') as f:
        return pickle.load(f)


def get_master_key():
    try:
        tree_root_node = load_tree()
        secret = get_node_secret(tree_root_node)
    except FileNotFoundError:
        print(f"{TREE_FILE} not found, creating tree from scratch (will create new master key)")
        tree_root_node, secret = create_tree_and_return_secret()
        print(f"Finished creating auth tree, now saving to {TREE_FILE}")
        save_tree(tree_root_node)
    return secret


def change_auth_method():
    # does not strictly need authentication as the derived passwords change with the auth method
    # changing auth method will always be possible by someone who controls the device as they can just delete the auth tree file
    tree_root_node, _ = create_tree_and_return_secret()
    print(f"Finished creating auth tree, now saving to {TREE_FILE}")
    save_tree(tree_root_node)


def create_password_node_with_secret(password: str, name: str) -> tuple[PasswordNode, bytes]:
    """
    Create a PasswordNode with a given password and name.
    
    Args:
        password: The password string
        name: The name for this node
    
    Returns:
        Tuple of (PasswordNode, secret)
    """
    secret = slow_hash(password.encode())
    verification_hash = fast_hash(secret)
    return PasswordNode(verification_hash, name), secret


def create_anyt_node_with_secrets(children_and_secrets: list[tuple[AuthNode, bytes]], threshold: int, name: str) -> tuple[AnyTNode, bytes]:
    """
    Create an AnyTNode with given children and their secrets.
    
    Args:
        children_and_secrets: List of (AuthNode, secret) tuples
        threshold: Number of children required to authenticate
        name: The name for this node
    
    Returns:
        Tuple of (AnyTNode, secret)
    """

    if threshold <= 0:
        raise ValueError(f"Threshold must be positive, got {threshold}")
    if threshold > len(children_and_secrets):
        raise ValueError(f"Threshold {threshold} exceeds number of children {len(children_and_secrets)}")

    children = [child for child, _ in children_and_secrets]
    shares = [secret for _, secret in children_and_secrets]
    
    sharer = NoLeakSecretSharer(shares, threshold)
    secret = sharer.get_secret({
        i: share
        for i, share in enumerate(shares)
    })
    
    return AnyTNode(verification_hash=fast_hash(secret),
                    name=name,
                    threshold=threshold,
                    children=children,
                    sharer_object=sharer), secret