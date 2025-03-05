import os
import json
import getpass
import hashlib
import secrets
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

BACKEND = default_backend()

class SecureFileVault:
    def __init__(self, vault_path):
        self.vault_path = vault_path
        self.master_key = None
        self.meta_data = None
        self.salt = None
        self.is_unlocked = False

    def _derive_key(self, password, salt):
        # PBKDF2-HMAC-SHA256 ile anahtar türetme
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=BACKEND
        )
        return kdf.derive(password.encode('utf-8'))

    def create_vault(self):
        if os.path.exists(self.vault_path):
            print("Vault already exists.")
            return

        password = getpass.getpass("Create vault password: ")
        confirm = getpass.getpass("Confirm vault password: ")
        if password != confirm:
            print("Passwords do not match.")
            return

        # Salt oluştur
        self.salt = secrets.token_bytes(16)
        self.master_key = self._derive_key(password, self.salt)

        # Başlangıçta boş meta verisi
        self.meta_data = {
            "files": []
        }

        # Boş meta veriyi kaydet
        self._save_vault()
        self.is_unlocked = True
        print("Vault created and unlocked successfully.")

    def open_vault(self):
        if not os.path.exists(self.vault_path):
            print("Vault does not exist.")
            return

        password = getpass.getpass("Enter vault password: ")
        with open(self.vault_path, "rb") as f:
            # vault format: salt (16 bytes) + encrypted_blob
            self.salt = f.read(16)
            encrypted_blob = f.read()

        key = self._derive_key(password, self.salt)
        aesgcm = AESGCM(key)

        # encrypted_blob ilk 12 bayt nonce, kalan kısım cipher text
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        try:
            decrypted_data = aesgcm.decrypt(nonce=nonce, data=ciphertext, associated_data=None)
        except Exception:
            print("Wrong password or vault corrupted.")
            return

        try:
            meta_json = json.loads(decrypted_data.decode('utf-8'))
        except:
            print("Meta data corrupted.")
            return

        self.master_key = key
        self.meta_data = meta_json
        self.is_unlocked = True
        print("Vault opened and unlocked successfully.")

    def lock_vault(self):
        self.master_key = None
        self.meta_data = None
        self.is_unlocked = False
        print("Vault locked.")

    def _save_vault(self):
        meta_bytes = json.dumps(self.meta_data).encode('utf-8')
        aesgcm = AESGCM(self.master_key)
        nonce = secrets.token_bytes(12)
        encrypted_blob = nonce + aesgcm.encrypt(nonce, meta_bytes, None)

        with open(self.vault_path, "wb") as f:
            f.write(self.salt)
            f.write(encrypted_blob)

    def add_file(self, filepath):
        if not self.is_unlocked:
            print("Vault is locked. Open it first.")
            return

        if not os.path.exists(filepath):
            print("File does not exist.")
            return

        with open(filepath, "rb") as ff:
            content = ff.read()

        # Dosya hash'i
        file_hash = hashlib.sha256(content).hexdigest()

        # Dosyayı AES-GCM ile şifrele
        iv = secrets.token_bytes(12)
        aesgcm = AESGCM(self.master_key)
        encrypted_content = aesgcm.encrypt(iv, content, None)

        new_file_entry = {
            "name": os.path.basename(filepath),
            "hash": file_hash,
            "iv": iv.hex(),
            "data": encrypted_content.hex()
        }

        self.meta_data["files"].append(new_file_entry)
        self._save_vault()
        print("File added to vault.")

    def list_files(self):
        if not self.is_unlocked:
            print("Vault is locked. Open it first.")
            return

        if not self.meta_data["files"]:
            print("No files in vault.")
            return

        for f in self.meta_data["files"]:
            print("Name:", f["name"], "Hash:", f["hash"])

    def extract_file(self, filename, output_path):
        if not self.is_unlocked:
            print("Vault is locked. Open it first.")
            return

        fentry = next((x for x in self.meta_data["files"] if x["name"] == filename), None)
        if fentry is None:
            print("File not found in vault.")
            return

        iv = bytes.fromhex(fentry["iv"])
        encrypted_content = bytes.fromhex(fentry["data"])

        aesgcm = AESGCM(self.master_key)
        try:
            content = aesgcm.decrypt(iv, encrypted_content, None)
        except Exception:
            print("Decryption failed, file may be corrupted.")
            return

        # Hash kontrolü
        file_hash = hashlib.sha256(content).hexdigest()
        if file_hash != fentry["hash"]:
            print("Integrity check failed! File may be tampered.")
            return

        with open(output_path, "wb") as out:
            out.write(content)

        print("File extracted successfully.")

    def remove_file(self, filename):
        if not self.is_unlocked:
            print("Vault is locked. Open it first.")
            return

        original_count = len(self.meta_data["files"])
        self.meta_data["files"] = [f for f in self.meta_data["files"] if f["name"] != filename]

        if len(self.meta_data["files"]) == original_count:
            print("File not found.")
        else:
            self._save_vault()
            print("File removed from vault.")

def usage():
    print("Usage:")
    print("  python vault.py create")
    print("  python vault.py open")
    print("  python vault.py lock")
    print("  python vault.py add <file_path>")
    print("  python vault.py list")
    print("  python vault.py extract <filename_in_vault> <output_path>")
    print("  python vault.py remove <filename_in_vault>")

if __name__ == "__main__":
    vault_path = "vault.bin"
    vault = SecureFileVault(vault_path)

    if len(sys.argv) < 2:
        usage()
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "create":
        vault.create_vault()
    elif cmd == "open":
        vault.open_vault()
    elif cmd == "lock":
        vault.lock_vault()
    elif cmd == "add":
        if len(sys.argv) < 3:
            usage()
        else:
            if not vault.is_unlocked:
                vault.open_vault()
            vault.add_file(sys.argv[2])
    elif cmd == "list":
        if not vault.is_unlocked:
            vault.open_vault()
        vault.list_files()
    elif cmd == "extract":
        if len(sys.argv) < 4:
            usage()
        else:
            if not vault.is_unlocked:
                vault.open_vault()
            vault.extract_file(sys.argv[2], sys.argv[3])
    elif cmd == "remove":
        if len(sys.argv) < 3:
            usage()
        else:
            if not vault.is_unlocked:
                vault.open_vault()
            vault.remove_file(sys.argv[2])
    else:
        usage()
