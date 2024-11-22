import sqlite3
from cryptography.fernet import Fernet
import base64
import hashlib

# Initialize the database
def initialize_db():
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY,
                        account TEXT NOT NULL,
                        password BLOB NOT NULL
                    )''')
    conn.commit()
    conn.close()

# Generate encryption key from master password
def generate_key(master_password):
    hashed_password = hashlib.sha256(master_password.encode()).digest()
    key = base64.urlsafe_b64encode(hashed_password)
    return key

# Store password in the database after encrypting it
def store_password(account, password, cipher_suite):
    encrypted_password = cipher_suite.encrypt(password.encode())
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (account, password) VALUES (?, ?)", (account, encrypted_password))
    conn.commit()
    conn.close()
    print("Password stored successfully!")

# Retrieve and decrypt password
def retrieve_password(account, cipher_suite):
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM passwords WHERE account = ?", (account,))
    result = cursor.fetchone()
    conn.close()
    if result:
        decrypted_password = cipher_suite.decrypt(result[0]).decode()
        print(f"Password for {account}: {decrypted_password}")
    else:
        print("Account not found!")

# Main program
def main():
    initialize_db()
    
    master_password = input("Enter the master password: ")
    key = generate_key(master_password)
    cipher_suite = Fernet(key)

    while True:
        choice = input("\nOptions:\n1. Store Password\n2. Retrieve Password\n3. Exit\nChoose an option: ")
        
        if choice == '1':
            account = input("Enter the account name: ")
            password = input("Enter the password: ")
            store_password(account, password, cipher_suite)
        
        elif choice == '2':
            account = input("Enter the account name to retrieve the password: ")
            retrieve_password(account, cipher_suite)
        
        elif choice == '3':
            print("Exiting the password manager.")
            break
        else:
            print("Invalid option. Please choose again.")

if __name__ == "__main__":
    main()
