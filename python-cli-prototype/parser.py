# pip install lark
from lark import Lark

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
    or_expression: and_expression ("or" and_expression)*
    
    and_expression: primary_expression ("and" primary_expression)*
    
    primary_expression: "any" POS_INT "of" "(" expr_list ")"
                      | "any" POS_INT "of" list_identifier
                      | "(" or_expression ")"
                      | identifier
    
    expr_list: or_expression ("," or_expression)*
    
    identifier: IDENTIFIER
    list_identifier: IDENTIFIER

    POS_INT: /[1-9][0-9]*/
    IDENTIFIER: /[a-zA-Z_][a-zA-Z0-9_]*/
    
    %import common.WS
    %ignore WS
    """, start='or_expression')
