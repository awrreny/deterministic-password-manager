#!/usr/bin/env python3
"""
GUI for Deterministic Password Manager
Integrates with the existing CLI prototype code
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
from collections import defaultdict
import threading
import time

# Import from existing modules
from gui_auth import GUITreefaAuth
from settings_handler import get_settings
from main import generate_password, verify_policy

try:
    import pyperclip
    clipboard_available = True
except ImportError:
    clipboard_available = False

POLICY_FILE = "pass_policies.json"
SITE_DATA_FILE = "site_data.json"

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Deterministic Password Manager")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Load settings and policies
        self.settings = get_settings()
        self.load_policies()
        self.load_site_data()
        
        # Variables
        self.master_key = None
        self.clipboard_timer = None
        
        # Create main frame with scrollbar
        self.create_widgets()
        
        # Don't load master key automatically - let user do it when ready
        
    def load_policies(self):
        """Load password policies from JSON file"""
        try:
            with open(POLICY_FILE, "r") as f:
                self.policies = json.load(f)
        except FileNotFoundError:
            messagebox.showerror("Error", f"Policy file {POLICY_FILE} not found!")
            self.policies = {}
    
    def load_site_data(self):
        """Load saved site data"""
        try:
            with open(SITE_DATA_FILE, "r") as f:
                self.site_data = json.load(f)
        except FileNotFoundError:
            self.site_data = {}
    
    def save_site_data(self):
        """Save site data to file"""
        with open(SITE_DATA_FILE, "w") as f:
            json.dump(self.site_data, f, indent=4)
    
    def create_widgets(self):
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        row = 0
        
        # Title
        title = ttk.Label(main_frame, text="Deterministic Password Manager", 
                         font=("Arial", 16, "bold"))
        title.grid(row=row, column=0, columnspan=3, pady=(0, 20))
        row += 1
        
        # Master key status
        self.master_key_label = ttk.Label(main_frame, text="Master Key: Not loaded", 
                                         foreground="red")
        self.master_key_label.grid(row=row, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        self.reload_key_btn = ttk.Button(main_frame, text="Reload Key", 
                                        command=self.load_master_key)
        self.reload_key_btn.grid(row=row, column=2, sticky=tk.E, pady=5)
        row += 1
        
        # Domain/Site input
        ttk.Label(main_frame, text="Domain/Site:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.domain_var = tk.StringVar()
        self.domain_entry = ttk.Entry(main_frame, textvariable=self.domain_var, width=40)
        self.domain_entry.grid(row=row, column=1, sticky="ew", pady=5)
        self.domain_entry.bind('<Return>', lambda e: self.on_domain_change())
        
        # Autocomplete button
        self.autocomplete_btn = ttk.Button(main_frame, text="↓", width=3,
                                          command=self.show_saved_sites)
        self.autocomplete_btn.grid(row=row, column=2, sticky=tk.W, padx=(5, 0), pady=5)
        row += 1
        
        # Username input
        ttk.Label(main_frame, text="Username:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(main_frame, textvariable=self.username_var, width=40)
        self.username_entry.grid(row=row, column=1, columnspan=2, sticky="ew", pady=5)
        row += 1
        
        # Counter input
        ttk.Label(main_frame, text="Counter:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.counter_var = tk.StringVar(value="0")
        self.counter_spin = ttk.Spinbox(main_frame, from_=0, to=999, 
                                       textvariable=self.counter_var, width=10)
        self.counter_spin.grid(row=row, column=1, sticky=tk.W, pady=5)
        row += 1
        
        # Policy selection
        ttk.Label(main_frame, text="Policy:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.policy_var = tk.StringVar()
        self.policy_combo = ttk.Combobox(main_frame, textvariable=self.policy_var, 
                                        state="readonly", width=37)
        self.update_policy_list()
        self.policy_combo.grid(row=row, column=1, columnspan=2, sticky="ew", pady=5)
        row += 1
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=row, column=0, columnspan=3, pady=20)
        
        self.generate_btn = ttk.Button(button_frame, text="Generate Password", 
                                      command=self.generate_password_gui)
        self.generate_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.save_btn = ttk.Button(button_frame, text="Save Site Data", 
                                  command=self.save_current_site)
        self.save_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_btn = ttk.Button(button_frame, text="Clear All", 
                                   command=self.clear_fields)
        self.clear_btn.pack(side=tk.LEFT)
        row += 1
        
        # Generated password display
        ttk.Label(main_frame, text="Generated Password:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                       state="readonly", width=40, show="*")
        self.password_entry.grid(row=row, column=1, sticky="ew", pady=5)
        
        # Show/hide toggle
        self.show_password_var = tk.BooleanVar()
        self.show_check = ttk.Checkbutton(main_frame, text="Show", 
                                         variable=self.show_password_var,
                                         command=self.toggle_password_visibility)
        self.show_check.grid(row=row, column=2, sticky=tk.W, padx=(5, 0), pady=5)
        row += 1
        
        # Copy and clear buttons
        copy_frame = ttk.Frame(main_frame)
        copy_frame.grid(row=row, column=0, columnspan=3, pady=10)
        
        if clipboard_available:
            self.copy_btn = ttk.Button(copy_frame, text="Copy to Clipboard", 
                                      command=self.copy_password)
            self.copy_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_pass_btn = ttk.Button(copy_frame, text="Clear Password", 
                                        command=self.clear_password)
        self.clear_pass_btn.pack(side=tk.LEFT)
        row += 1
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                                   relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(20, 0))
        
        # Focus on domain entry
        self.domain_entry.focus()
    
    def update_policy_list(self):
        """Update the policy combobox with available policies"""
        policy_names = list(self.policies.keys())
        self.policy_combo['values'] = policy_names
        if policy_names and not self.policy_var.get():
            self.policy_var.set("default" if "default" in policy_names else policy_names[0])
    
    def load_master_key(self):
        """Load the master key using the GUI authentication system"""
        try:
            self.status_var.set("Loading master key...")
            self.root.update()
            
            # Create GUI authentication handler
            gui_auth = GUITreefaAuth(self.root)
            
            # This will show GUI authentication dialogs
            self.master_key = gui_auth.get_master_key()
            
            self.master_key_label.config(text="Master Key: Loaded ✓", foreground="green")
            self.status_var.set("Master key loaded successfully")
            
        except KeyboardInterrupt:
            self.master_key = None
            self.master_key_label.config(text="Master Key: Cancelled", foreground="red")
            self.status_var.set("Master key loading cancelled")
            
        except Exception as e:
            self.master_key = None
            self.master_key_label.config(text="Master Key: Error", foreground="red")
            self.status_var.set(f"Error loading master key: {str(e)}")
            messagebox.showerror("Authentication Error", f"Failed to load master key: {str(e)}")
    
    def on_domain_change(self):
        """Handle domain field changes - try to autofill from saved data"""
        domain = self.domain_var.get().strip()
        if domain and domain in self.site_data:
            saved_data = self.site_data[domain]
            if isinstance(saved_data, list) and saved_data:
                data = saved_data[0]  # Use first saved entry
                
                if 'username' in data:
                    self.username_var.set(data['username'])
                if 'counter' in data:
                    self.counter_var.set(str(data['counter']))
                if 'policy' in data:
                    self.policy_var.set(data['policy'])
                
                self.status_var.set(f"Autofilled data for {domain}")
    
    def show_saved_sites(self):
        """Show a dropdown of saved sites"""
        if not self.site_data:
            messagebox.showinfo("No Data", "No saved sites found")
            return
        
        # Create a simple selection dialog
        sites = list(self.site_data.keys())
        
        # Simple implementation - could be enhanced with a proper dropdown
        site_list = "\n".join(f"{i}: {site}" for i, site in enumerate(sites))
        selected = messagebox.askquestion("Saved Sites", 
                                         f"Available sites:\n{site_list}\n\nShow in domain field?")
        if selected == 'yes' and sites:
            self.domain_var.set(sites[0])
            self.on_domain_change()
    
    def generate_password_gui(self):
        """Generate password using the existing password generation logic"""
        if not self.master_key:
            messagebox.showerror("Error", "Master key not loaded! Please reload the master key.")
            return
        
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showerror("Error", "Domain is required!")
            return
        
        username = self.username_var.get().strip()
        
        try:
            counter = int(self.counter_var.get())
        except ValueError:
            messagebox.showerror("Error", "Counter must be a number!")
            return
        
        policy_name = self.policy_var.get()
        if policy_name not in self.policies:
            messagebox.showerror("Error", f"Invalid policy: {policy_name}")
            return
        
        policy = self.policies[policy_name]
        
        try:
            self.status_var.set("Generating password...")
            self.root.update()
            
            # Use the existing password generation function
            password = generate_password(self.master_key, domain, username, counter, policy)
            
            self.password_var.set(password)
            self.status_var.set("Password generated successfully")
            
            # Auto-clear after configured time if clipboard available
            if clipboard_available and self.settings.get("passwordCopyTime"):
                self.schedule_password_clear(self.settings.get("passwordCopyTime", 15))
            
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
            messagebox.showerror("Generation Error", f"Failed to generate password: {str(e)}")
    
    def save_current_site(self):
        """Save current site data"""
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showerror("Error", "Domain is required to save!")
            return
        
        data = {}
        
        username = self.username_var.get().strip()
        if username:
            data['username'] = username
        
        try:
            counter = int(self.counter_var.get())
            data['counter'] = counter
        except ValueError:
            pass
        
        policy_name = self.policy_var.get()
        if policy_name:
            data['policy'] = policy_name
        
        if not data:
            messagebox.showwarning("Warning", "No data to save!")
            return
        
        # Initialize site data structure
        if domain not in self.site_data:
            self.site_data[domain] = []
        
        # Check if this exact data already exists
        if data not in self.site_data[domain]:
            self.site_data[domain].append(data)
            self.save_site_data()
            self.status_var.set(f"Site data saved for {domain}")
            messagebox.showinfo("Success", "Site data saved successfully!")
        else:
            messagebox.showinfo("Info", "This site data already exists.")
    
    def copy_password(self):
        """Copy password to clipboard"""
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "No password to copy!")
            return
        
        try:
            pyperclip.copy(password)
            self.status_var.set("Password copied to clipboard")
            
            # Schedule clipboard clear
            clear_time = self.settings.get("passwordCopyTime", 15)
            self.schedule_clipboard_clear(clear_time)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")
    
    def schedule_clipboard_clear(self, seconds):
        """Schedule clipboard clearing after specified seconds"""
        if self.clipboard_timer:
            self.clipboard_timer.cancel()
        
        def clear_clipboard():
            try:
                pyperclip.copy("")
                self.status_var.set("Clipboard cleared")
            except:
                pass
        
        self.clipboard_timer = threading.Timer(seconds, clear_clipboard)
        self.clipboard_timer.start()
        
        self.status_var.set(f"Clipboard will be cleared in {seconds} seconds")
    
    def schedule_password_clear(self, seconds):
        """Schedule password field clearing after specified seconds"""
        def clear_password():
            self.password_var.set("")
            self.status_var.set("Password cleared")
        
        timer = threading.Timer(seconds, clear_password)
        timer.start()
    
    def toggle_password_visibility(self):
        """Toggle password field visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def clear_password(self):
        """Clear the password field"""
        self.password_var.set("")
        self.status_var.set("Password cleared")
    
    def clear_fields(self):
        """Clear all input fields"""
        self.domain_var.set("")
        self.username_var.set("")
        self.counter_var.set("0")
        self.password_var.set("")
        if self.policies:
            default_policy = "default" if "default" in self.policies else list(self.policies.keys())[0]
            self.policy_var.set(default_policy)
        self.status_var.set("Fields cleared")
        self.domain_entry.focus()
    
    def on_closing(self):
        """Handle application closing"""
        if self.clipboard_timer:
            self.clipboard_timer.cancel()
        
        # Clear clipboard if it might contain a password
        if clipboard_available:
            try:
                pyperclip.copy("")
            except:
                pass
        
        self.root.destroy()


def main():
    """Main GUI entry point"""
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    
    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Start the GUI
    root.mainloop()


if __name__ == "__main__":
    main()
