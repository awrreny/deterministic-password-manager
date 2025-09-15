from lark.visitors import Transformer
from .parser import parser, extract_identifiers
from .treefa_utils import create_password_node_with_secret, create_anyt_node_with_secrets
from getpass import getpass


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
        for i, pwd in enumerate(self.list_passwords[list_name], start=1):
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
    

def _get_confirmed_password(prompt: str, confirm_passwords: bool, indent = False) -> str:
    """Get a password with optional confirmation."""
    
    indent_str = '    ' if indent else ''

    while True:
        password = getpass(f"{indent_str}{prompt}")
        if not confirm_passwords:
            return password

        confirm = getpass(f"{indent_str}Confirm {prompt} ")
        if password == confirm:
            return password
        else:
            print("Passwords don't match. Please try again.")


def collect_passwords(single_identifiers: list[str], list_identifiers: list[str], confirm_passwords: bool = False) -> tuple[dict[str, str], dict[str, list[str]]]:
    """
    Collect passwords from user for single and list identifiers.
    
    Args:
        single_identifiers: List of single identifier names
        list_identifiers: List of list identifier names
        confirm_passwords: If True, prompt user to enter each password twice for confirmation
    
    Returns:
        Tuple of (single_passwords_dict, list_passwords_dict)
    """
    single_passwords = {}
    list_passwords = {}
    
    # Collect passwords for single identifiers
    for identifier in single_identifiers:
        password = _get_confirmed_password(f"Enter password for '{identifier}': ", confirm_passwords)
        single_passwords[identifier] = password
    
    # Collect passwords for list identifiers
    for list_identifier in list_identifiers:
        print(f"\nEnter passwords for list '{list_identifier}' or leave blank to finish")
        passwords = []
        index = 1
        
        while True:
            password = _get_confirmed_password(f"Password {index}: ", confirm_passwords, indent=True)
            if password == "":
                break
            passwords.append(password)
            index += 1
        
        list_passwords[list_identifier] = passwords
    
    return single_passwords, list_passwords

# single_passwords should be mapped to a PasswordNode
# list_passwords should be mapped to a list of PasswordNodes, all of which are children of a single AnyOfListNode


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
