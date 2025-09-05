# pip install lark
from lark import Lark
from lark.visitors import Visitor

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
