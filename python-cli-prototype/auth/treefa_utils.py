from dataclasses import dataclass
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