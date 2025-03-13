import hashlib
import tkinter as tk
from tkinter import messagebox, ttk

def generate_hash():
    text = entry_text.get("1.0", tk.END).strip()
    if not text:
        messagebox.showwarning("Warning", "Please enter text to hash.")
        return

    algo = hash_algorithm.get()
    if algo == "MD5":
        hash_result = hashlib.md5(text.encode()).hexdigest()
    elif algo == "SHA-1":
        hash_result = hashlib.sha1(text.encode()).hexdigest()
    elif algo == "SHA-256":
        hash_result = hashlib.sha256(text.encode()).hexdigest()
    elif algo == "SHA-512":
        hash_result = hashlib.sha512(text.encode()).hexdigest()
    else:
        messagebox.showerror("Error", "Invalid hash algorithm selected.")
        return

    entry_result.delete("1.0", tk.END)
    entry_result.insert(tk.END, hash_result)

def copy_result():
    text = entry_result.get("1.0", tk.END).strip()
    if text:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        messagebox.showinfo("Copied", "Hash copied to clipboard.")

root = tk.Tk()
root.title("Hash Generator")
root.geometry("500x400")
root.config(bg="#121212")

label_text = tk.Label(root, text="Enter text:", font=("Helvetica", 12), bg="#121212", fg="#BB86FC")
label_text.pack(pady=5)
entry_text = tk.Text(root, height=4, width=50, bg="#1E1E1E", fg="white", insertbackground="white")
entry_text.pack(pady=5)

label_algo = tk.Label(root, text="Select Hash Algorithm:", font=("Helvetica", 12), bg="#121212", fg="#BB86FC")
label_algo.pack(pady=5)
hash_algorithm = ttk.Combobox(root, values=["MD5", "SHA-1", "SHA-256", "SHA-512"], state="readonly", font=("Helvetica", 12))
hash_algorithm.pack(pady=5)
hash_algorithm.current(2)

button_generate = tk.Button(root, text="Generate Hash", font=("Helvetica", 12), bg="#BB86FC", fg="black", command=generate_hash)
button_generate.pack(pady=10)

label_result = tk.Label(root, text="Hash Result:", font=("Helvetica", 12), bg="#121212", fg="#BB86FC")
label_result.pack(pady=5)
entry_result = tk.Text(root, height=4, width=50, bg="#1E1E1E", fg="white", insertbackground="white")
entry_result.pack(pady=5)

button_copy = tk.Button(root, text="Copy", font=("Helvetica", 12), bg="#FBC02D", fg="black", command=copy_result)
button_copy.pack(pady=10)

root.mainloop()
