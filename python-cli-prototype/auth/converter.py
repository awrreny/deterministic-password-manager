from lark.visitors import Transformer
from .parser import parser, extract_identifiers, collect_passwords
from .treefa import PasswordNode, AnyTNode, create_password_node_with_secret, create_anyt_node_with_secrets, get_node_secret
from crypto_primitives import slow_hash, fast_hash


class TreefaConverter(Transformer):
    def __init__(self, single_passwords: dict[str, str], list_passwords: dict[str, list[str]]):
        """
        single_passwords: dict mapping identifier names to password strings
        list_passwords: dict mapping list identifier names to lists of password strings
        """
        self.single_passwords = single_passwords
        self.list_passwords = list_passwords
    
    def or_expr(self, children):
        if len(children) == 1:
            return children[0]
        # OR is shorthand for "any 1 of (...)"
        children_and_secrets = [child for child in children]
        node, secret = create_anyt_node_with_secrets(children_and_secrets, threshold=1, name=f"any_1_of_{len(children)}")
        return (node, secret)
    
    def and_expr(self, children):
        if len(children) == 1:
            return children[0]
        # AND is shorthand for "any N of (...)" where N = len(children)
        children_and_secrets = [child for child in children]
        node, secret = create_anyt_node_with_secrets(children_and_secrets, threshold=len(children), name=f"all_{len(children)}")
        return (node, secret)
    
    def any_of_list(self, children):
        # children: [INT, list_identifier_result] 
        count = int(children[0])
        list_name = children[1]  # This is now the processed result from list_identifier
        
        if count <= 0:
            raise ValueError(f"Threshold must be positive, got {count}")
        if count > len(self.list_passwords[list_name]):
            raise ValueError(f"Threshold {count} exceeds number of children {len(self.list_passwords[list_name])}")

        # Convert list of passwords to list of (PasswordNode, secret) tuples
        password_nodes_and_secrets = []
        for i, pwd in enumerate(self.list_passwords[list_name]):
            node, secret = create_password_node_with_secret(pwd, f"{list_name}_{i}")
            password_nodes_and_secrets.append((node, secret))
        
        node, secret = create_anyt_node_with_secrets(password_nodes_and_secrets, threshold=count, name=f"any_{count}_of_{list_name}")
        return (node, secret)
    
    def any_of_children(self, children):
        # children: [INT, expr_list]
        count = int(children[0])
        child_nodes_and_secrets = children[1]  # expr_list result

        if count <= 0:
            raise ValueError(f"Threshold must be positive, got {count}")
        if count > len(child_nodes_and_secrets):
            raise ValueError(f"Threshold {count} exceeds number of children {len(child_nodes_and_secrets)}")

        node, secret = create_anyt_node_with_secrets(child_nodes_and_secrets, threshold=count, name=f"any_{count}_of_{len(child_nodes_and_secrets)}")
        return (node, secret)
    
    def expr_list(self, children):
        return children  # Just return list of (node, secret) tuples
    
    def identifier(self, children):
        name = str(children[0])  # CNAME token
        password = self.single_passwords[name]
        node, secret = create_password_node_with_secret(password, name)
        return (node, secret)
    
    def list_identifier(self, children):
        # Return just the name string, not the PasswordNodes
        # The PasswordNodes will be created in any_of_list
        name = str(children[0])  # CNAME token
        return name


def parse_to_treefa(expression_string: str, confirm_passwords: bool = False):
    """
    Parse expression string, collect passwords, and convert to treefa tree.
    
    Args:
        expression_string: The logical expression to parse
        confirm_passwords: If True, prompt user to enter each password twice
    
    Returns:
        Tuple of (root treefa node, root secret)
    """

    parse_tree = parser.parse(expression_string)
    single_identifiers, list_identifiers = extract_identifiers(parse_tree)
    single_passwords, list_passwords = collect_passwords(
        single_identifiers, list_identifiers, confirm_passwords
    )

    converter = TreefaConverter(single_passwords, list_passwords)
    return converter.transform(parse_tree)


if __name__ == "__main__":
    tree, secret = parse_to_treefa("any 2 of users")
    print(f"Master secret: {secret.hex()}")
    
    print("Authentication test:")
    secret_2 = get_node_secret(tree)
    print(f"Derived secret: {secret_2.hex()}")
