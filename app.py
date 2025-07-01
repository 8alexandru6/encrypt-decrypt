from cryptography.fernet import Fernet
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk  
from functools import partial

def generate_key():
    key = Fernet.generate_key()
    with open("encryption.key", "wb") as key_file:
        key_file.write(key)
    messagebox.showinfo("Success", "Key generated and saved to encryption.key")


def load_key():
    try:
        with open("encryption.key", "rb") as key_file:
            key = key_file.read()
        return key
    except FileNotFoundError:
        messagebox.showerror("Error", "Encryption key file (encryption.key) not found. Generate a key first.")
        return None


def encrypt_file(filename, key):
    try:
        f = Fernet(key)
        with open(filename, "rb") as file:
            file_data = file.read()
        encrypted_data = f.encrypt(file_data)
        with open(filename + ".encrypted", "wb") as file:
            file.write(encrypted_data)
        messagebox.showinfo("Success", f"Successfully encrypted {filename} to {filename}.encrypted")
    except FileNotFoundError:
        messagebox.showerror("Error", f"File '{filename}' not found.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during encryption: {e}")


def decrypt_file(filename, key):
    try:
        f = Fernet(key)
        with open(filename, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = f.decrypt(encrypted_data)
        original_filename = filename.replace(".encrypted", "")
        with open(original_filename, "wb") as file:
            file.write(decrypted_data)
        messagebox.showinfo("Success", f"Successfully decrypted {filename} to {original_filename}")
    except FileNotFoundError:
        messagebox.showerror("Error", f"File '{filename}' not found.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during decryption: {e}")
    except ValueError:
        messagebox.showerror("Error", "Incorrect key or file corrupted. Check the key and file.")

class FileEncryptorGUI:
    def __init__(self, master):
        self.master = master
        master.title("File Encryptor/Decryptor")
        master.geometry("500x300")  
        master.configure(bg="#f0f0f0") 

        self.key = None  

        self.button_style = {
            "bg": "#4CAF50",  
            "fg": "white",
            "font": ("Arial", 10, "bold"),
            "relief": "raised",  
            "bd": 2,  
            "padx": 10, 
            "pady": 5,
        }
        self.label_style = {
            "bg": "#f0f0f0",
            "fg": "#333333",
            "font": ("Arial", 10),
        }
        self.entry_style = {
            "font": ("Arial", 10),
            "relief": "sunken", 
            "bd": 1, 
        }

        self.browse_button_style = {
            "font": ("Arial", 9),
            "relief": "raised",
            "bd": 1,
            "padx": 5,
            "pady": 2,
        }


        self.button_frame = tk.Frame(master, bg="#f0f0f0") 
        self.button_frame.grid(row=0, column=0, columnspan=3, pady=10) 

        self.generate_key_button = tk.Button(self.button_frame, text="Generate Key", command=self.generate_key, **self.button_style)
        self.generate_key_button.pack(side=tk.LEFT, padx=5) 

        self.load_key_button = tk.Button(self.button_frame, text="Load Key", command=self.load_key, **self.button_style)
        self.load_key_button.pack(side=tk.LEFT, padx=5)

        self.file_frame = tk.Frame(master, bg="#f0f0f0")
        self.file_frame.grid(row=1, column=0, columnspan=3, pady=5) 

        self.file_label = tk.Label(self.file_frame, text="Selected File:", **self.label_style)
        self.file_label.pack(side=tk.LEFT, padx=5)

        self.file_var = tk.StringVar()
        self.file_entry = tk.Entry(self.file_frame, textvariable=self.file_var, width=40, **self.entry_style)
        self.file_entry.pack(side=tk.LEFT, padx=5)

        self.browse_button = tk.Button(self.file_frame, text="Browse", command=self.browse_file, **self.browse_button_style)
        self.browse_button.pack(side=tk.LEFT, padx=5)  

        self.action_frame = tk.Frame(master, bg="#f0f0f0")
        self.action_frame.grid(row=2, column=0, columnspan=3, pady=10)

        self.encrypt_button = tk.Button(self.action_frame, text="Encrypt", command=self.encrypt_file, **self.button_style)
        self.encrypt_button.pack(side=tk.LEFT, padx=10) 

        self.decrypt_button = tk.Button(self.action_frame, text="Decrypt", command=self.decrypt_file, **self.button_style)
        self.decrypt_button.pack(side=tk.LEFT, padx=10)


    def browse_file(self):
        filepath = filedialog.askopenfilename()
        self.file_var.set(filepath)


    def generate_key(self):
        generate_key()

    def load_key(self):
        self.key = load_key()  

    def encrypt_file(self):
        if not self.key:
            messagebox.showerror("Error", "Please load or generate a key first.")
            return
        filename = self.file_var.get() 
        if not filename:
            messagebox.showerror("Error", "Please select a file to encrypt")
            return
        encrypt_file(filename, self.key)

    def decrypt_file(self):
        if not self.key:
            messagebox.showerror("Error", "Please load or generate a key first.")
            return
        filename = self.file_var.get()  
        if not filename:
            messagebox.showerror("Error", "Please select a file to decrypt")
            return
        decrypt_file(filename, self.key)



root = tk.Tk()
gui = FileEncryptorGUI(root)
root.mainloop()