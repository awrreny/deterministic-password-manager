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

# Test cases to show tree structure
if __name__ == "__main__":
    print("CURRENT GRAMMAR PARSE TREES:")
    print("=" * 40)
    
    test1 = "any 1 of (id1, id2)"
    print(f"\nTest 1: '{test1}'")
    tree1 = parser.parse(test1)
    print(tree1.pretty())
    
    test2 = "id1 or any 2 of (id3 and id4)"
    print(f"\nTest 2: '{test2}'")  
    tree2 = parser.parse(test2)
    print(tree2.pretty())

    test3 = "id1 or any 2 of list1"
    print(f"\nTest 3: '{test3}'")
    tree3 = parser.parse(test3)
    print(tree3.pretty())
