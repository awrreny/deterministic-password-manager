#!/usr/bin/env python3
"""Show parse trees for OR and AND expressions."""

from parser import parser, extract_identifiers

def show_tree(description, test_input):
    """Parse and display the tree structure."""
    print(f"\n{description}")
    print(f"Input: '{test_input}'")
    try:
        tree = parser.parse(test_input)
        print("Parse Tree:")
        print(tree.pretty())
        single_ids, list_ids = extract_identifiers(tree)
        print("Single Identifiers:", single_ids)
        print("List Identifiers:", list_ids)
        print("-" * 40)
    except Exception as e:
        print(f"Error: {e}")

def main():
    print("=" * 60)
    print("PARSE TREE EXAMPLES FOR OR AND AND")
    print("=" * 60)
    
    show_tree("Simple OR", "id1 or id2")
    show_tree("Simple AND", "id1 and id2")
    show_tree("Mixed (AND has higher precedence)", "id1 or id2 and id3")
    show_tree("Parentheses change precedence", "(id1 or id2) and id3")
    show_tree("Multiple OR", "id1 or id2 or id3")
    show_tree("Multiple AND", "id1 and id2 and id3")
    show_tree("Complex nesting", "any 1 of (id1 or id2, id3 and id4)")
    show_tree("Mixed with any expressions", "any 1 of (id1, id2) or any 2 of (id3, id4)")
    show_tree("any_of_list", "any 1 of l1 or i2")
    show_tree("Repeated identifiers", "id1 and id2 or id1 and id3")
    show_tree("Repeated List identifiers", "any 1 of l1 or any 2 of l1")

if __name__ == "__main__":
    main()
