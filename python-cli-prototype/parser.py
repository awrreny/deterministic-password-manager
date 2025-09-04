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
