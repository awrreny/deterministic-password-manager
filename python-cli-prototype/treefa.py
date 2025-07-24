# 'tree-factor authentication'
# zero-knowledge tree thing that only gives the 'root secret' if all conditions are met
# this zero-knowledge is enforced cryptographically rather than by a server
# e.g for local password managers
from dataclasses import dataclass
from inpututil import get_input, choose_option
from crypto_primitives import slow_hash, fast_hash, NoLeakSecretSharer


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
                password = get_input(f"Enter password for node '{name}'\n> ")
                # there are 2 hashes here - the first is more of an encoding or an extending
                # the 2nd is to check if the correct password was entered, but is only for usability (to notify user if password is wrong)
                # it has no cryptographic role in terms of getting the node secret (or any other secret)
                secret = slow_hash(password.encode())
                if fast_hash(secret) == verification_hash:
                    return secret
                else:
                    print("Incorrect password")


        case AnyTNode(verification_hash=verification_hash, threshold=threshold, children=children, sharer_object=sharer_object):
            known_shares = dict()
            auth_options = {
                i: child.name
                for (i, child) in enumerate(children)
            }
            while threshold > 0:
                node_index = choose_option(auth_options,
                                            text1=f"Select which method to authenticate with. ({threshold} remaining)",
                                            inp_type=int,
                                            )
                known_shares[node_index] = get_node_secret(children[node_index])
                auth_options.pop(node_index)
                threshold -= 1

            secret = sharer_object.get_secret(known_shares)

            if fast_hash(secret) != verification_hash:
                raise ValueError(f"Node '{name}' failed verification")

        
            
# v = testnode("a1")
# u = testnode("c")
# w = testnode("x")
# x = create_anyt_node([v,u,w], 2, "hi")
# print(get_node_secret(x))


def get_master_key():
    # placeholder
    return get_node_secret(testnode("placeholder"))