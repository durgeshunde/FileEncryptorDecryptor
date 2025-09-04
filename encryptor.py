from cryptography.fernet import Fernet
import os
import time
from colorama import init, Fore, Style

init(autoreset=True)  # Initialize colorama

LOG_FILE = "encryptor.log"

# Logging function
def log_event(message):
    with open(LOG_FILE, "a") as log:
        log.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

# Generate & save key
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    log_event("Key generated and saved as secret.key")
    print(Fore.GREEN + f"✅ Key generated successfully!")
    print(Fore.CYAN + f"Key saved at: {os.path.abspath('secret.key')}")

# Load key
def load_key():
    if not os.path.exists("secret.key"):
        print(Fore.RED + "❌ Key file not found. Please generate a key first.")
        return None
    return open("secret.key", "rb").read()

# Encrypt file
def encrypt_file(filename, key):
    if not os.path.exists(filename):
        print(Fore.RED + f"❌ File '{filename}' not found.")
        return
    fernet = Fernet(key)
    with open(filename, "rb") as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    out_file = filename + ".encrypted"
    if os.path.exists(out_file):
        overwrite = input(Fore.YELLOW + "⚠ File already exists. Overwrite? (y/n): ").lower()
        if overwrite != "y":
            print(Fore.CYAN + "Cancelled encryption.")
            return
    with open(out_file, "wb") as enc_file:
        enc_file.write(encrypted)
    log_event(f"Encrypted file: {filename}")
    print(Fore.GREEN + f"✅ File encrypted successfully!")
    print(Fore.CYAN + f"Encrypted file saved at: {os.path.abspath(out_file)}")

# Decrypt file
def decrypt_file(filename, key):
    if not os.path.exists(filename):
        print(Fore.RED + f"❌ File '{filename}' not found.")
        return
    fernet = Fernet(key)
    with open(filename, "rb") as enc_file:
        encrypted = enc_file.read()
    try:
        decrypted = fernet.decrypt(encrypted)
    except Exception as e:
        print(Fore.RED + f"❌ Error decrypting file: {e}")
        return
    
    # Properly restore original filename
    if filename.endswith(".encrypted"):
        out_file = filename.rsplit(".encrypted", 1)[0]  # removes ".encrypted" safely
    else:
        out_file = filename + "_decrypted"
    
    if os.path.exists(out_file):
        overwrite = input(Fore.YELLOW + "⚠ File already exists. Overwrite? (y/n): ").lower()
        if overwrite != "y":
            print(Fore.CYAN + "Cancelled decryption.")
            return
    
    with open(out_file, "wb") as dec_file:
        dec_file.write(decrypted)
    
    log_event(f"Decrypted file: {filename}")
    print(Fore.GREEN + f"✅ File decrypted successfully!")
    print(Fore.CYAN + f"Decrypted file saved at: {os.path.abspath(out_file)}")

# Main menu
def main():
    while True:
        print(Fore.MAGENTA + "\n" + "="*50)
        print(Fore.MAGENTA + "   🔐 Personal File Encryption Dashboard 🔐")
        print(Fore.MAGENTA + "="*50)
        print(Fore.CYAN + "1. Generate Key")
        print(Fore.CYAN + "2. Encrypt File")
        print(Fore.CYAN + "3. Decrypt File")
        print(Fore.CYAN + "4. Exit")
        choice = input(Fore.YELLOW + "Enter choice: ")

        if choice == "1":
            generate_key()
        elif choice == "2":
            key = load_key()
            if key:
                filename = input(Fore.YELLOW + "Enter file name to encrypt (full path or same folder): ")
                encrypt_file(filename, key)
        elif choice == "3":
            key = load_key()
            if key:
                filename = input(Fore.YELLOW + "Enter file name to decrypt (full path or same folder): ")
                decrypt_file(filename, key)
        elif choice == "4":
            print(Fore.MAGENTA + "👋 Exiting... Stay secure!")
            break
        else:
            print(Fore.RED + "❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    main()