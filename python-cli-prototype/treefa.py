# 'tree-factor authentication'
import hashlib


def get_master_key():
    password = input("Enter your master password: ").strip()
    
    # PLACEHOLDER TODO
    return hashlib.sha256(password.encode('utf-8')).digest()