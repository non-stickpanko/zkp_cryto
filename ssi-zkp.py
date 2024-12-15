from hashlib import sha256
import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel
import sqlite3
import json

# Mock function for hash computation (Merkle tree hash and general purposes)
def compute_hash(data):
    return sha256(data.encode()).hexdigest()

# Step 1: Medical Records and Merkle Tree Construction
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

# Step 2: Database Setup
class DatabaseManager:
    def __init__(self):
        self.conn = sqlite3.connect("medical_records.db")
        self.cursor = self.conn.cursor()
        self._setup_tables()

    def _setup_tables(self):
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS patient_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                eligibility INTEGER NOT NULL,
                age INTEGER NOT NULL,
                access_details TEXT
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS patient_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                doctor TEXT NOT NULL,
                diagnosis TEXT NOT NULL,
                treatment TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def add_patient(self, name, eligibility, age, date, doctor, diagnosis, treatment):
        self.cursor.execute("INSERT INTO patient_details (name, eligibility, age, access_details) VALUES (?, ?, ?, ?)", (name, eligibility, age, ""))
        self.cursor.execute("INSERT INTO patient_records (date, doctor, diagnosis, treatment) VALUES (?, ?, ?, ?)", (date, doctor, diagnosis, treatment))
        self.conn.commit()

    def get_patients(self):
        return self.cursor.execute("SELECT id, name FROM patient_details").fetchall()

    def get_eligibility(self, patient_id):
        result = self.cursor.execute("SELECT eligibility FROM patient_details WHERE id = ?", (patient_id,)).fetchone()
        return result[0] if result else 0

    def get_age(self, patient_id):
        result = self.cursor.execute("SELECT age FROM patient_details WHERE id = ?", (patient_id,)).fetchone()
        return result[0] if result else None

    def get_record(self, patient_id):
        result = self.cursor.execute("SELECT date, doctor, diagnosis, treatment FROM patient_records WHERE id = ?", (patient_id,)).fetchone()
        return result if result else None

    def update_access_details(self, patient_id, details):
        self.cursor.execute("UPDATE patient_details SET access_details = ? WHERE id = ?", (details, patient_id))
        self.conn.commit()

# Step 3: ZKP Setup for Access Rights
class MedicalRecordsAccess:
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
class MedicalAccessApp:
    def __init__(self, root, db_manager):
        self.root = root
        self.db_manager = db_manager

        self.root.title("Medical Records Access")
        self.root.attributes('-fullscreen', True)

        # Header
        self.header = tk.Label(root, text="Medical Records Access Portal", font=("Arial", 24), pady=20)
        self.header.pack()

        # Instruction
        self.instruction = tk.Label(root, text="Select a patient to access their medical record:", font=("Arial", 16))
        self.instruction.pack()

        # List of Patients
        self.listbox = tk.Listbox(root, font=("Arial", 14), width=50, height=10)
        self.populate_patients()
        self.listbox.pack(pady=20)

        # Access Button
        self.access_button = tk.Button(root, text="Access Record", font=("Arial", 14), command=self.ask_for_age)
        self.access_button.pack(pady=10)

        # Exit Button
        self.exit_button = tk.Button(root, text="Exit", font=("Arial", 14), command=root.quit)
        self.exit_button.pack(pady=10)

    def populate_patients(self):
        self.listbox.delete(0, tk.END)
        patients = self.db_manager.get_patients()
        for patient_id, name in patients:
            self.listbox.insert(tk.END, f"{patient_id}: {name}")

    def ask_for_age(self):
        selected = self.listbox.curselection()
        if not selected:
            messagebox.showerror("Error", "Please select a patient.")
            return

        patient_id = int(self.listbox.get(selected[0]).split(":")[0])
        self.prompt_age(patient_id)

    def prompt_age(self, patient_id):
        age = simpledialog.askinteger("Age Verification", "Please enter the patient's age:")
        if age is None:
            return

        actual_age = self.db_manager.get_age(patient_id)
        if age == actual_age:
            self.show_record_window(patient_id)
        else:
            messagebox.showerror("Error", "Age verification failed. Access denied.")

    def show_record_window(self, patient_id):
        record = self.db_manager.get_record(patient_id)
        if not record:
            messagebox.showerror("Error", "No record found for this patient.")
            return

        date, doctor, diagnosis, treatment = record
        record_content = f"Date: {date}\nDoctor: {doctor}\nDiagnosis: {diagnosis}\nTreatment: {treatment}"
        proof_data = MedicalRecordsAccess([record_content]).generate_proof(0)
        proof_details = json.dumps(proof_data, indent=4)

        # Update access details in the database
        access_details = f"Accessed on: {proof_details}"
        self.db_manager.update_access_details(patient_id, access_details)

        # Create a new window to display the record
        record_window = Toplevel(self.root)
        record_window.title("Patient Record")
        record_window.geometry("600x400")

        tk.Label(record_window, text="Patient Record", font=("Arial", 18), pady=10).pack()
        record_text = tk.Text(record_window, font=("Arial", 14), wrap=tk.WORD, height=15, width=70)
        record_text.insert(tk.END, record_content)
        record_text.pack()
        record_text.configure(state="disabled")

        tk.Label(record_window, text="Proof Details", font=("Arial", 18), pady=10).pack()
        proof_text = tk.Text(record_window, font=("Arial", 12), wrap=tk.WORD, height=15, width=70)
        proof_text.insert(tk.END, proof_details)
        proof_text.pack()
        proof_text.configure(state="disabled")

# Example Usage
if __name__ == "__main__":
    # Database setup
    db_manager = DatabaseManager()

    # Populate database with sample data (if empty)
    if not db_manager.get_patients():
        db_manager.add_patient("Alice", 1, 25, "2024-12-10", "Dr. Smith", "Flu", "Rest and hydration")
        db_manager.add_patient("Bob", 0, 17, "2024-12-11", "Dr. Adams", "Cold", "Over-the-counter meds")
        db_manager.add_patient("Charlie", 1, 40, "2024-12-12", "Dr. Johnson", "Back Pain", "Physical therapy")
        db_manager.add_patient("Dana", 1, 30, "2024-12-13", "Dr. Lee", "Allergy", "Antihistamines")

    # Create and run the Tkinter app
    root = tk.Tk()
    app = MedicalAccessApp(root, db_manager)
    root.mainloop()
