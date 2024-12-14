import hashlib
import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import re

# Utility Functions
def hash_data(data: str) -> str:
    """Hash input data using SHA-256."""
    return hashlib.sha256(data.encode()).hexdigest()

# Issuer Module
def issue_credential(attributes: dict):
    """Generate credentials for given attributes."""
    hashed_attributes = {
        key: hash_data(f"{key}:{value}") for key, value in attributes.items()
    }
    concatenated_hashes = ''.join(hashed_attributes.values())
    root_hash = hash_data(concatenated_hashes)
    private_key = ec.generate_private_key(ec.SECP256R1())
    signature = private_key.sign(root_hash.encode(), ec.ECDSA(hashes.SHA256()))

    return {
        "root_hash": root_hash,
        "attributes": attributes,
        "hashed_attributes": hashed_attributes,
        "issuer_signature": signature,
    }

# Holder Module
def generate_proof(credentials, attribute_key, condition):
    """Simplified proof generation: Check condition and simulate proof."""
    if attribute_key not in credentials["attributes"]:
        raise ValueError("Attribute not found in credentials.")

    attribute_value = int(credentials["attributes"][attribute_key])
    is_condition_met = int(attribute_value > condition)
    proof = {
        "attribute_key": attribute_key,
        "attribute_value": attribute_value,
        "condition": condition,
        "is_condition_met": is_condition_met
    }

    return proof

# Verifier Module
def verify_proof(credentials, proof):
    """Simplified proof verification."""
    attribute_key = proof["attribute_key"]
    if attribute_key not in credentials["attributes"]:
        return False

    expected_value = int(credentials["attributes"][attribute_key])
    is_condition_met = proof["is_condition_met"] == int(expected_value > proof["condition"])
    return is_condition_met

class SocialMediaRecoveryApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Social Media Account Recovery")
        self.root.geometry("400x500")
        self.root.configure(bg='#f0f2f5')
        
        # Application-wide variables
        self.credentials = None
        self.proof = None
        
        self.create_main_window()
    
    def create_main_window(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main frame
        main_frame = tk.Frame(self.root, bg='#f0f2f5')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Logo or Title
        title_label = tk.Label(main_frame, text="Social Media Recovery", 
                               font=('Arial', 20, 'bold'), 
                               bg='#f0f2f5', 
                               fg='#1877f2')
        title_label.pack(pady=(0, 20))
        
        # Buttons
        button_style = {
            'font': ('Arial', 12),
            'width': 25,
            'bg': '#1877f2',
            'fg': 'white',
            'activebackground': '#166fe5',
            'activeforeground': 'white',
            'relief': tk.FLAT,
            'borderwidth': 0
        }
        
        issue_btn = tk.Button(main_frame, text="Issue Credentials", 
                              command=self.open_issue_window, **button_style)
        issue_btn.pack(pady=10)
        
        generate_proof_btn = tk.Button(main_frame, text="Generate Proof", 
                                       command=self.open_generate_proof_window, **button_style)
        generate_proof_btn.pack(pady=10)
        
        verify_proof_btn = tk.Button(main_frame, text="Verify Proof", 
                                     command=self.open_verify_proof_window, **button_style)
        verify_proof_btn.pack(pady=10)
    
    def create_styled_entry(self, parent, label_text):
        """Create a styled entry with label"""
        frame = tk.Frame(parent, bg='#f0f2f5')
        frame.pack(fill='x', pady=5)
        
        label = tk.Label(frame, text=label_text, 
                         font=('Arial', 10), 
                         bg='#f0f2f5')
        label.pack(anchor='w')
        
        entry = tk.Entry(frame, 
                         font=('Arial', 12), 
                         relief=tk.FLAT, 
                         bg='white', 
                         highlightthickness=1, 
                         highlightcolor='#1877f2')
        entry.pack(fill='x')
        
        return entry
    
    def open_issue_window(self):
        # Create a new top-level window
        issue_window = tk.Toplevel(self.root)
        issue_window.title("Issue Credentials")
        issue_window.geometry("400x500")
        issue_window.configure(bg='#f0f2f5')
        
        # Main frame
        main_frame = tk.Frame(issue_window, bg='#f0f2f5')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Title
        title_label = tk.Label(main_frame, text="Issue Account Credentials", 
                               font=('Arial', 16, 'bold'), 
                               bg='#f0f2f5', 
                               fg='#1877f2')
        title_label.pack(pady=(0, 20))
        
        # Entries
        self.name_entry = self.create_styled_entry(main_frame, "Full Name")
        self.age_entry = self.create_styled_entry(main_frame, "Age")
        
        # Issue Button
        issue_btn = tk.Button(main_frame, text="Issue Credentials", 
                              command=lambda: self.issue_credentials(issue_window), 
                              font=('Arial', 12),
                              width=25,
                              bg='#1877f2',
                              fg='white',
                              activebackground='#166fe5',
                              activeforeground='white',
                              relief=tk.FLAT)
        issue_btn.pack(pady=20)
        
        # Back Button
        back_btn = tk.Button(main_frame, text="Back to Main Menu", 
                             command=issue_window.destroy, 
                             font=('Arial', 10),
                             bg='#f0f2f5',
                             fg='#1877f2',
                             activebackground='#f0f2f5',
                             activeforeground='#166fe5',
                             relief=tk.FLAT)
        back_btn.pack()
    
    def issue_credentials(self, window):
        try:
            name = self.name_entry.get()
            age = self.age_entry.get()
            
            # Validate inputs
            if not name or not age:
                messagebox.showerror("Error", "Please fill in all fields.")
                return
            
            if not re.match(r'^[A-Za-z\s]+$', name):
                messagebox.showerror("Error", "Name should contain only letters.")
                return
            
            if not age.isdigit() or int(age) < 13 or int(age) > 120:
                messagebox.showerror("Error", "Please enter a valid age.")
                return
            
            attributes = {"name": name, "age": age}
            self.credentials = issue_credential(attributes)
            messagebox.showinfo("Success", "Credentials Issued Successfully!")
            window.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to issue credentials: {e}")
    
    def open_generate_proof_window(self):
        if not self.credentials:
            messagebox.showerror("Error", "Please issue credentials first!")
            return
        
        # Create a new top-level window
        proof_window = tk.Toplevel(self.root)
        proof_window.title("Generate Proof")
        proof_window.geometry("400x500")
        proof_window.configure(bg='#f0f2f5')
        
        # Main frame
        main_frame = tk.Frame(proof_window, bg='#f0f2f5')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Title
        title_label = tk.Label(main_frame, text="Generate Account Recovery Proof", 
                               font=('Arial', 16, 'bold'), 
                               bg='#f0f2f5', 
                               fg='#1877f2')
        title_label.pack(pady=(0, 20))
        
        # Hint about current credentials
        hint_label = tk.Label(main_frame, 
                              text=f"Current Credentials:\nName: {self.credentials['attributes']['name']}\nAge: {self.credentials['attributes']['age']}", 
                              font=('Arial', 10), 
                              bg='#f0f2f5', 
                              fg='#555')
        hint_label.pack(pady=(0, 10))
        
        # Entries
        self.attribute_entry = self.create_styled_entry(main_frame, "Attribute to Prove (e.g., age)")
        self.condition_entry = self.create_styled_entry(main_frame, "Condition Value (e.g., 18)")
        
        # Generate Proof Button
        generate_btn = tk.Button(main_frame, text="Generate Proof", 
                                 command=lambda: self.generate_proof(proof_window), 
                                 font=('Arial', 12),
                                 width=25,
                                 bg='#1877f2',
                                 fg='white',
                                 activebackground='#166fe5',
                                 activeforeground='white',
                                 relief=tk.FLAT)
        generate_btn.pack(pady=20)
        
        # Back Button
        back_btn = tk.Button(main_frame, text="Back to Main Menu", 
                             command=proof_window.destroy, 
                             font=('Arial', 10),
                             bg='#f0f2f5',
                             fg='#1877f2',
                             activebackground='#f0f2f5',
                             activeforeground='#166fe5',
                             relief=tk.FLAT)
        back_btn.pack()
    
    def generate_proof(self, window):
        try:
            attribute_key = self.attribute_entry.get()
            condition_str = self.condition_entry.get()
            
            # Validate inputs
            if not attribute_key or not condition_str:
                messagebox.showerror("Error", "Please fill in all fields.")
                return
            
            condition = int(condition_str)
            
            self.proof = generate_proof(self.credentials, attribute_key, condition)
            messagebox.showinfo("Success", f"Proof generated for {attribute_key} > {condition}.")
            window.destroy()
        except ValueError:
            messagebox.showerror("Error", "Invalid condition. Please enter a number.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate proof: {e}")
    
    def open_verify_proof_window(self):
        if not self.proof or not self.credentials:
            messagebox.showerror("Error", "Please generate a proof first!")
            return
        
        # Create a new top-level window
        verify_window = tk.Toplevel(self.root)
        verify_window.title("Verify Proof")
        verify_window.geometry("400x500")
        verify_window.configure(bg='#f0f2f5')
        
        # Main frame
        main_frame = tk.Frame(verify_window, bg='#f0f2f5')
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Title
        title_label = tk.Label(main_frame, text="Verify Account Recovery Proof", 
                               font=('Arial', 16, 'bold'), 
                               bg='#f0f2f5', 
                               fg='#1877f2')
        title_label.pack(pady=(0, 20))
        
        # Proof Details
        details_frame = tk.Frame(main_frame, bg='#f0f2f5')
        details_frame.pack(fill='x', pady=10)
        
        details = [
            f"Attribute: {self.proof['attribute_key']}",
            f"Value: {self.proof['attribute_value']}",
            f"Condition: > {self.proof['condition']}"
        ]
        
        for detail in details:
            tk.Label(details_frame, 
                     text=detail, 
                     font=('Arial', 10), 
                     bg='#f0f2f5', 
                     anchor='w').pack(fill='x')
        
        # Verify Button
        verify_btn = tk.Button(main_frame, text="Verify Proof", 
                               command=lambda: self.verify_proof(verify_window), 
                               font=('Arial', 12),
                               width=25,
                               bg='#1877f2',
                               fg='white',
                               activebackground='#166fe5',
                               activeforeground='white',
                               relief=tk.FLAT)
        verify_btn.pack(pady=20)
        
        # Back Button
        back_btn = tk.Button(main_frame, text="Back to Main Menu", 
                             command=verify_window.destroy, 
                             font=('Arial', 10),
                             bg='#f0f2f5',
                             fg='#1877f2',
                             activebackground='#f0f2f5',
                             activeforeground='#166fe5',
                             relief=tk.FLAT)
        back_btn.pack()
    
    def verify_proof(self, window):
        try:
            is_valid = verify_proof(self.credentials, self.proof)
            if is_valid:
                messagebox.showinfo("Success", "Account Recovery Proof Validated!")
                window.destroy()
            else:
                messagebox.showerror("Invalid", "The proof is invalid.")
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {e}")

# Main Execution
if __name__ == "__main__":
    root = tk.Tk()
    app = SocialMediaRecoveryApp(root)
    root.mainloop()