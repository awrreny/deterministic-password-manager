# pip install lark
from lark import Lark
from lark.visitors import Visitor
import getpass


"""
original language:
start E
nonterminals E, L
productions:
E ->  E and E
    | E or E
    | any NUM of (L)
    | any NUM of list_identifier
    | (E)
    | identifier
    
L ->  E
    | E, L

unambiguous language:
start O
nonterminals O, A, E, L
productions:
O ->  A
    | A or O

A ->  E
    | E and A

E ->  any NUM of (L)
    | any NUM of list_identifier
    | (O)
    | identifier

L ->  O
    | O, L

(or, and are associative)
"""

parser = Lark(r"""
    ?or_expr: and_expr ("or" and_expr)*
    
    ?and_expr: any_expr ("and" any_expr)*
    
    ?any_expr: any_of_list
            | any_of_children
            | "(" or_expr ")"
            | identifier
              
    any_of_list: "any" INT "of" list_identifier
    any_of_children: "any" INT "of" "(" expr_list ")"
    
    expr_list: or_expr ("," or_expr)*

    identifier: CNAME
    list_identifier: CNAME

    %import common.CNAME
    %import common.INT
    %import common.WS
    %ignore WS
    """, start='or_expr')


class IdentifierExtractor(Visitor):
    def __init__(self):
        self.single_identifiers = []
        self.list_identifiers = []
    
    def identifier(self, tree):
        name = str(tree.children[0])  # CNAME token
        if name not in self.single_identifiers:
            self.single_identifiers.append(name)
    
    def list_identifier(self, tree):
        name = str(tree.children[0])  # CNAME token
        if name not in self.list_identifiers:
            self.list_identifiers.append(name)

def extract_identifiers(parse_tree) -> tuple[list[str], list[str]]:
    extractor = IdentifierExtractor()
    extractor.visit(parse_tree)
    return extractor.single_identifiers, extractor.list_identifiers


def _get_confirmed_password(prompt: str, confirm_passwords: bool) -> str:
    """Get a password with optional confirmation."""
    
    while True:
        password = getpass.getpass(prompt)
        if not confirm_passwords:
            return password
        
        confirm = getpass.getpass(f"Confirm {prompt.lower()}")
        if password == confirm:
            return password
        else:
            print("Passwords don't match. Please try again.")


# can factor into other file (e.g inpututils.py)
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
            password = _get_confirmed_password(f"  Password {index}: ", confirm_passwords)
            if password == "":
                break
            passwords.append(password)
            index += 1
        
        list_passwords[list_identifier] = passwords
    
    return single_passwords, list_passwords

# single_passwords should be mapped to a PasswordNode
# list_passwords should be mapped to a list of PasswordNodes, all of which are children of a single AnyOfListNode