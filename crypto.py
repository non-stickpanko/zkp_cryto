import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel
import hashlib
import json
from cryptography.fernet import Fernet

# Helper function to compute a hash
def compute_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Merkle Tree Implementation
class MerkleTree:
    def __init__(self, data_list):
        """
        Initialize the Merkle Tree with a list of data items.
        :param data_list: List of strings (user data).
        """
        self.leaves = [compute_hash(data) for data in data_list]  # Hash all data items
        self.root = self.build_tree(self.leaves)

    def build_tree(self, hashes):
        """
        Build the Merkle Tree and return the root hash.
        :param hashes: List of leaf hashes.
        :return: Root hash of the Merkle Tree.
        """
        if len(hashes) == 1:
            return hashes[0]  # Root hash

        # Pairwise hash combination
        next_level = []
        for i in range(0, len(hashes), 2):
            # If odd number of hashes, duplicate the last one
            left = hashes[i]
            right = hashes[i + 1] if i + 1 < len(hashes) else left
            combined_hash = compute_hash(left + right)  # Concatenate and hash
            next_level.append(combined_hash)

        return self.build_tree(next_level)

    def get_root(self):
        """
        Get the Merkle root hash.
        :return: Root hash.
        """
        return self.root

# ZKP Setup for User Authentication
class UserAuthenticationZKP:
    def __init__(self, records):
        self.records = records
        self.tree = MerkleTree(records)  # Create a Merkle Tree from records
        self.merkle_root = self.tree.get_root()

    def generate_proof(self, record_index):
        """
        Generate a Merkle proof for a specific record.
        :param record_index: Index of the record in the original data.
        :return: Merkle proof with sibling hashes.
        """
        proof = []
        hashes = self.tree.leaves
        current_index = record_index

        # Generate proof by traversing up the tree
        while len(hashes) > 1:
            next_level = []
            for i in range(0, len(hashes), 2):
                left = hashes[i]
                right = hashes[i + 1] if i + 1 < len(hashes) else left

                # Add sibling to proof
                if i == current_index or i + 1 == current_index:
                    proof.append(right if i == current_index else left)

                # Compute parent hash
                combined_hash = compute_hash(left + right)
                next_level.append(combined_hash)

            # Move to next level
            current_index //= 2
            hashes = next_level

        return proof

    def verify_proof(self, record, proof):
        """
        Verify the Merkle proof for a specific record.
        :param record: The original record data.
        :param proof: List of sibling hashes in the proof.
        :return: True if the proof is valid, False otherwise.
        """
        current_hash = compute_hash(record)

        for sibling_hash in proof:
            # Combine hashes based on sibling's position
            current_hash = compute_hash(current_hash + sibling_hash)

        return current_hash == self.merkle_root

# Encryption/Decryption Setup
class Encryption:
    def __init__(self):
        self.key = Fernet.generate_key()  # Generate encryption key
        self.cipher_suite = Fernet(self.key)

    def encrypt_data(self, data):
        """Encrypt data using the cipher suite."""
        return self.cipher_suite.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data):
        """Decrypt data using the cipher suite."""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()

# Database Manager to Handle Users
class DatabaseManager:
    def __init__(self, db_file):
        self.db_file = db_file
        self.load_data()

    def load_data(self):
        try:
            with open(self.db_file, 'r') as f:
                self.data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.data = {"users": []}
        self.users = self.data.get("users", [])

    def save_data(self):
        with open(self.db_file, 'w') as f:
            json.dump(self.data, f, indent=4)

    def add_user(self, name, password_hash, encrypted_data, merkle_root):
        if any(user['name'] == name for user in self.users):
            return False  # Name already exists
        self.data["users"].append({
            "name": name,
            "password_hash": password_hash,
            "user_data": encrypted_data,
            "merkle_root": merkle_root
        })
        self.save_data()
        return True

    def get_user(self, name):
        return next((user for user in self.users if user['name'] == name), None)

# Tkinter User Interface
class UserVerificationApp:
    def __init__(self, root, db_manager, encryption):
        self.root = root
        self.db_manager = db_manager
        self.encryption = encryption

        self.root.title("User Identity Verification")
        self.root.geometry("400x300")

        # Welcome message
        self.header = tk.Label(root, text="Welcome to User Verification Portal", font=("Arial", 16), pady=20)
        self.header.pack()

        # Register and Login Buttons
        self.register_button = tk.Button(root, text="Register", font=("Arial", 14), command=self.register)
        self.register_button.pack(pady=10)

        self.login_button = tk.Button(root, text="Login", font=("Arial", 14), command=self.login)
        self.login_button.pack(pady=10)

        # Exit Button
        self.exit_button = tk.Button(root, text="Exit", font=("Arial", 14), command=root.quit)
        self.exit_button.pack(pady=10)

    def register(self):
        name = simpledialog.askstring("Name", "Enter your name:")
        if not name:
            return

        password = simpledialog.askstring("Password", "Enter a new password:", show="*")
        if not password:
            return

        # Collect user details after registration
        dob = simpledialog.askstring("Date of Birth", "Enter your Date of Birth (DD-MM-YYYY):")
        doctor = simpledialog.askstring("Doctor", "Enter your doctor's name:")
        medications = simpledialog.askstring("Medications", "Enter your medications:")
        last_appointment = simpledialog.askstring("Last Appointment", "Enter the date of your last appointment:")

        # Combine records for Merkle hashing
        records = [
            f"DOB: {dob}",
            f"Doctor: {doctor}",
            f"Medications: {medications}",
            f"Last Appointment: {last_appointment}"
        ]
        zkp = UserAuthenticationZKP(records)

        # Encrypt additional user details
        encrypted_data = self.encryption.encrypt_data("\n".join(records))

        # Hash the password
        hashed_password = compute_hash(password)

        # Add user to the database with Merkle root
        if self.db_manager.add_user(name, hashed_password, encrypted_data, zkp.merkle_root):
            messagebox.showinfo("Success", "Registration successful!")
        else:
            messagebox.showerror("Error", "Name already exists.")

    def login(self):
        name = simpledialog.askstring("Name", "Enter your name:")
        if not name:
            return

        password = simpledialog.askstring("Password", "Enter your password:", show="*")
        if not password:
            return

        # Hash the entered password
        hashed_password = compute_hash(password)
        user = self.db_manager.get_user(name)

        if user and user['password_hash'] == hashed_password:
            messagebox.showinfo("Success", "Login successful!")
            self.show_user_details(user)
        else:
            messagebox.showerror("Error", "Incorrect name or password.")

    def show_user_details(self, user):
        # Decrypt and display user details
        decrypted_data = self.encryption.decrypt_data(user['user_data'])

        # Create a new window to display user details
        verification_window = Toplevel(self.root)
        verification_window.title("User Details")
        verification_window.geometry("600x400")

        # Display decrypted details
        tk.Label(verification_window, text="User Details", font=("Arial", 14), pady=10).pack()
        tk.Label(verification_window, text=decrypted_data, font=("Arial", 12), pady=10).pack()

# Example Usage
if __name__ == "__main__":
    # Database setup
    db_manager = DatabaseManager("users_database.json")
    encryption = Encryption()

    # Create and run the Tkinter app
    root = tk.Tk()
    app = UserVerificationApp(root, db_manager, encryption)
    root.mainloop()
