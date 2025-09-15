"""
GUI Authentication Module for Treefa
Provides GUI dialogs for password input instead of terminal-based input
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Dict, Any
import pickle
from crypto_primitives import slow_hash, fast_hash
from auth.treefa_utils import AuthNode, PasswordNode, AnyTNode

TREE_FILE = "treefa_tree.pkl"

class PasswordDialog:
    """Custom password dialog for GUI authentication"""
    
    def __init__(self, parent, title, prompt):
        self.result = None
        self.canceled = False
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x150")
        self.dialog.resizable(False, False)
        
        # Handle modal behavior more carefully
        self.dialog.transient(parent)
        self.dialog.grab_set()  # Make it modal
        
        # Center the dialog
        self.center_window()
        
        # Create widgets
        self.create_widgets(prompt)
        
        # Focus on password entry
        self.password_entry.focus()
        
        # Handle window close
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_cancel)
        
        # Bind Enter key
        self.dialog.bind('<Return>', lambda e: self.on_ok())
        self.dialog.bind('<Escape>', lambda e: self.on_cancel())
    
    def center_window(self):
        """Center the dialog on the parent window"""
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (self.dialog.winfo_width() // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def create_widgets(self, prompt):
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Prompt label
        prompt_label = ttk.Label(main_frame, text=prompt, wraplength=350)
        prompt_label.pack(pady=(0, 10))
        
        # Password entry
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                       show="*", width=40)
        self.password_entry.pack(pady=(0, 20))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack()
        
        ttk.Button(button_frame, text="OK", command=self.on_ok).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT)
    
    def on_ok(self):
        self.result = self.password_var.get()
        self.dialog.destroy()
    
    def on_cancel(self):
        self.canceled = True
        self.dialog.destroy()


class AuthenticationChoiceDialog:
    """Dialog for choosing authentication methods in threshold nodes"""
    
    def __init__(self, parent, title, prompt, options: Dict[int, str]):
        self.result = None
        self.canceled = False
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("450x300")
        self.dialog.resizable(True, True)
        
        # Handle modal behavior more carefully
        self.dialog.transient(parent)
        self.dialog.grab_set()  # Make it modal
        
        # Center the dialog
        self.center_window()
        
        # Create widgets
        self.create_widgets(prompt, options)
        
        # Handle window close
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_cancel)
        
        # Bind keys
        self.dialog.bind('<Return>', lambda e: self.on_ok())
        self.dialog.bind('<Escape>', lambda e: self.on_cancel())
    
    def center_window(self):
        """Center the dialog on the parent window"""
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (self.dialog.winfo_width() // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def create_widgets(self, prompt, options):
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Prompt label
        prompt_label = ttk.Label(main_frame, text=prompt, wraplength=400)
        prompt_label.pack(pady=(0, 10))
        
        # Options frame with scrollbar
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Listbox for options
        self.listbox = tk.Listbox(options_frame, height=8)
        scrollbar = ttk.Scrollbar(options_frame, orient=tk.VERTICAL, command=self.listbox.yview)
        self.listbox.config(yscrollcommand=scrollbar.set)
        
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate listbox
        self.option_mapping = {}
        for index, (key, value) in enumerate(options.items()):
            display_text = f"[{key}] {value}"
            self.listbox.insert(tk.END, display_text)
            self.option_mapping[index] = key
        
        # Select first item by default
        if options:
            self.listbox.selection_set(0)
        
        # Only allow selection, no action on click/double-click
        # Remove any click bindings to prevent the modal dialog issues
        
        # Focus the listbox
        self.listbox.focus()
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack()
        
        self.select_btn = ttk.Button(button_frame, text="Select", command=self.on_ok)
        self.select_btn.pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel).pack(side=tk.LEFT)
    
    # Remove the on_click method since we don't want any click actions
    
    def on_ok(self):
        selection = self.listbox.curselection()
        if selection:
            list_index = selection[0]
            self.result = self.option_mapping[list_index]
        self.dialog.destroy()
    
    def on_cancel(self):
        self.canceled = True
        self.dialog.destroy()


class GUITreefaAuth:
    """GUI version of the treefa authentication system"""
    
    def __init__(self, parent_window):
        self.parent = parent_window
    
    def get_node_secret(self, node: AuthNode) -> bytes:
        """GUI version of get_node_secret"""
        match node:
            case PasswordNode(verification_hash=verification_hash, name=name):
                while True:
                    # Show password dialog
                    dialog = PasswordDialog(
                        self.parent,
                        "Authentication Required",
                        f"Enter password for: {name}"
                    )
                    self.parent.wait_window(dialog.dialog)
                    
                    if dialog.canceled:
                        raise KeyboardInterrupt("Authentication cancelled by user")
                    
                    password = dialog.result
                    if not password:
                        continue
                    
                    # Verify password
                    secret = slow_hash(password.encode())
                    if fast_hash(secret) == verification_hash:
                        return secret
                    else:
                        messagebox.showerror("Authentication Error", 
                                           "Incorrect password. Please try again.")

            case AnyTNode(verification_hash=verification_hash, threshold=threshold, 
                         children=children, sharer_object=sharer_object, name=name):
                known_shares = dict()
                auth_options = {
                    i: child.name
                    for (i, child) in enumerate(children)
                }
                remaining_threshold = threshold
                
                while remaining_threshold > 0:
                    # Show choice dialog
                    dialog = AuthenticationChoiceDialog(
                        self.parent,
                        "Select Authentication Method",
                        f"Select which method to authenticate with.\n({remaining_threshold} remaining)",
                        auth_options
                    )
                    self.parent.wait_window(dialog.dialog)
                    
                    if dialog.canceled:
                        raise KeyboardInterrupt("Authentication cancelled by user")
                    
                    node_index = dialog.result
                    if node_index is None:
                        continue
                    
                    # Get secret for selected node
                    try:
                        known_shares[node_index] = self.get_node_secret(children[node_index])
                        auth_options.pop(node_index)
                        remaining_threshold -= 1
                    except KeyboardInterrupt:
                        raise  # Re-raise cancellation
                    except Exception as e:
                        messagebox.showerror("Authentication Error", 
                                           f"Failed to authenticate with {children[node_index].name}: {str(e)}")

                # Verify the combined secret
                secret = sharer_object.get_secret(known_shares)
                if fast_hash(secret) != verification_hash:
                    raise ValueError(f"Node '{name}' failed verification")
                
                return secret
            
            case _:
                raise NotImplementedError(f"Unknown node type: {type(node)}")
    
    def load_tree(self) -> AuthNode:
        """Load the authentication tree from file"""
        try:
            with open(TREE_FILE, "rb") as f:
                return pickle.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Authentication tree file '{TREE_FILE}' not found. "
                                  "Please run the CLI version first to create the authentication tree.")
    
    def get_master_key(self) -> bytes:
        """GUI version of get_master_key"""
        try:
            tree_root_node = self.load_tree()
            secret = self.get_node_secret(tree_root_node)
            return secret
        except FileNotFoundError:
            # If no tree exists, show an error and suggest using CLI first
            messagebox.showerror(
                "No Authentication Tree", 
                f"No authentication tree found ({TREE_FILE}).\n\n"
                "Please run the CLI version first to set up your authentication:\n"
                "python main.py\n\n"
                "This will create your master key and authentication tree."
            )
            raise
        except KeyboardInterrupt:
            # User cancelled authentication
            raise
        except Exception as e:
            messagebox.showerror("Authentication Error", f"Failed to load master key: {str(e)}")
            raise
