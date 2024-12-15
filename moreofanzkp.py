import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel
import hashlib
import json

# Helper function to compute a hash
def compute_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


# Step 1: Merkle Tree Construction for ZKP
class MerkleTree:
    def __init__(self, records):
        self.records = records
        self.leaves = [compute_hash(record) for record in records]
        self.tree = self._build_tree(self.leaves)

    def _build_tree(self, leaves):
        tree = [leaves]
        while len(leaves) > 1:
            next_level = []
            for i in range(0, len(leaves), 2):
                left = leaves[i]
                right = leaves[i + 1] if i + 1 < len(leaves) else left
                next_level.append(compute_hash(left + right))
            leaves = next_level
            tree.append(leaves)
        return tree

    def get_root(self):
        return self.tree[-1][0] if self.tree else None

    def get_proof(self, index):
        proof = []
        for level in self.tree[:-1]:
            sibling_index = index ^ 1
            proof.append(level[sibling_index] if sibling_index < len(level) else None)
            index //= 2
        return proof


# Step 2: Database Manager to Handle Users
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
        if "users" not in self.data:
            self.data["users"] = []
        self.users = self.data.get("users", [])

    def save_data(self):
        with open(self.db_file, 'w') as f:
            json.dump(self.data, f, indent=4)

    def add_user(self, username, password_hash):
        if any(user['username'] == username for user in self.users):
            return False  # Username already exists
        self.data["users"].append({"username": username, "password_hash": password_hash})
        self.save_data()
        return True

    def get_user(self, username):
        return next((user for user in self.users if user['username'] == username), None)


# Step 3: ZKP Setup for User Authentication
class UserAuthenticationZKP:
    def __init__(self, records):
        self.merkle_tree = MerkleTree(records)

    def generate_proof(self, record_index):
        record_hash = self.merkle_tree.leaves[record_index]
        proof = self.merkle_tree.get_proof(record_index)
        return {
            "record_hash": record_hash,
            "proof": proof,
            "root": self.merkle_tree.get_root(),
            "index": record_index
        }


# Step 4: Tkinter User Interface
class UserVerificationApp:
    def __init__(self, root, db_manager):
        self.root = root
        self.db_manager = db_manager

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
        username = simpledialog.askstring("Username", "Enter a new username:")
        if not username:
            return

        password = simpledialog.askstring("Password", "Enter a new password:", show="*")
        if not password:
            return

        # Hash the password
        hashed_password = compute_hash(password)

        # Add user to the database
        if self.db_manager.add_user(username, hashed_password):
            messagebox.showinfo("Success", "Registration successful!")
        else:
            messagebox.showerror("Error", "Username already exists.")

    def login(self):
        username = simpledialog.askstring("Username", "Enter your username:")
        if not username:
            return

        password = simpledialog.askstring("Password", "Enter your password:", show="*")
        if not password:
            return

        # Hash the entered password and find the user
        hashed_password = compute_hash(password)
        user = self.db_manager.get_user(username)

        if user and user['password_hash'] == hashed_password:
            messagebox.showinfo("Success", "Login successful!")
            self.show_verification_window(username, password)
        else:
            messagebox.showerror("Error", "Incorrect username or password.")

    def show_verification_window(self, username, password):
        # Prepare the Merkle tree for the password proof
        password_hash = compute_hash(password)
        proof_data = UserAuthenticationZKP([password_hash]).generate_proof(0)

        proof_details = json.dumps(proof_data, indent=4)

        # Create a new window to display the proof
        verification_window = Toplevel(self.root)
        verification_window.title("Verification Proof")
        verification_window.geometry("600x400")

        tk.Label(verification_window, text="Verification Proof", font=("Arial", 18), pady=10).pack()
        proof_text = tk.Text(verification_window, font=("Arial", 12), wrap=tk.WORD, height=15, width=70)
        proof_text.insert(tk.END, proof_details)
        proof_text.pack()
        proof_text.configure(state="disabled")


# Example Usage
if __name__ == "__main__":
    # Database setup
    db_manager = DatabaseManager("users_database.json")

    # Create and run the Tkinter app
    root = tk.Tk()
    app = UserVerificationApp(root, db_manager)
    root.mainloop()
