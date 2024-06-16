import sqlite3
from cryptography.fernet import Fernet
import base64
import hashlib
import random
import string
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk


def generate_key(password):
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode('utf-8')).digest())
    return key


def init_db(conn):
    with conn:
       
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                master_password_hash TEXT NOT NULL
            )
        ''')
        
      
        conn.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')

        
        cursor = conn.execute("PRAGMA table_info(passwords);")
        columns = [info[1] for info in cursor.fetchall()]
        if 'user_id' not in columns:
            conn.execute("ALTER TABLE passwords ADD COLUMN user_id INTEGER")


def add_user(conn, username, master_password):
    master_password_hash = hashlib.sha256(master_password.encode('utf-8')).hexdigest()
    with conn:
        conn.execute('''
            INSERT INTO users (username, master_password_hash)
            VALUES (?, ?)
        ''', (username, master_password_hash))


def authenticate_user(conn, username, master_password):
    master_password_hash = hashlib.sha256(master_password.encode('utf-8')).hexdigest()
    cur = conn.execute('SELECT id FROM users WHERE username = ? AND master_password_hash = ?', (username, master_password_hash))
    row = cur.fetchone()
    if row:
        return row[0]
    return None


def add_password(conn, user_id, key, service, username, password):
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode('utf-8'))
    with conn:
        conn.execute('''
            INSERT INTO passwords (user_id, service, username, password)
            VALUES (?, ?, ?, ?)
        ''', (user_id, service, username, encrypted_password))


def get_password(conn, user_id, key, service):
    fernet = Fernet(key)
    cur = conn.execute('SELECT username, password FROM passwords WHERE user_id = ? AND service = ?', (user_id, service))
    row = cur.fetchone()
    if row:
        username, encrypted_password = row
        decrypted_password = fernet.decrypt(encrypted_password).decode('utf-8')
        return username, decrypted_password
    return None


def delete_password(conn, user_id, service):
    with conn:
        conn.execute('DELETE FROM passwords WHERE user_id = ? AND service = ?', (user_id, service))


def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))


def check_password_strength(password):
    if len(password) < 8:
        return "Weak"
    elif any(c.isdigit() for c in password) and any(c.isalpha() for c in password) and any(c in string.punctuation for c in password):
        return "Strong"
    else:
        return "Medium"


class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("700x600")
        self.configure(bg='#f0f0f0') 

        self.conn = sqlite3.connect('maor_password.db')
        init_db(self.conn)

        self.user_id = None
        self.key = None

        self.login_screen()

    def login_screen(self):
        self.clear_widgets()
        
      
        header_label = tk.Label(self, text="Password Manager", font=('Helvetica', 24), bg='#4CAF50', fg='white', padx=10, pady=10)
        header_label.pack(fill=tk.X)

      
        login_frame = tk.Frame(self, bg='#f0f0f0')
        login_frame.pack(pady=50)

        username_label = tk.Label(login_frame, text="Username:", bg='#f0f0f0', font=('Arial', 14))
        username_label.grid(row=0, column=0, padx=10, pady=5)
        self.username_entry = tk.Entry(login_frame, font=('Arial', 14))
        self.username_entry.grid(row=0, column=1, padx=10, pady=5)

        password_label = tk.Label(login_frame, text="Master Password:", bg='#f0f0f0', font=('Arial', 14))
        password_label.grid(row=1, column=0, padx=10, pady=5)
        self.password_entry = tk.Entry(login_frame, show='*', font=('Arial', 14))
        self.password_entry.grid(row=1, column=1, padx=10, pady=5)

        login_button = tk.Button(login_frame, text="Login", command=self.login, bg='#2196F3', fg='white', font=('Arial', 14))
        login_button.grid(row=2, column=0, columnspan=2, pady=10)

        register_button = tk.Button(login_frame, text="Register", command=self.register, bg='#4CAF50', fg='white', font=('Arial', 14))
        register_button.grid(row=3, column=0, columnspan=2, pady=10)

       
        footer_label = tk.Label(self, text="© 2024 Maor Password Manager Inc.", bg='#333', fg='white', font=('Arial', 10), anchor=tk.W)
        footer_label.pack(fill=tk.X, side=tk.BOTTOM, ipady=5)

    def register(self):
        username = self.username_entry.get()
        master_password = self.password_entry.get()

        if not username or not master_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        add_user(self.conn, username, master_password)
        messagebox.showinfo("Success", "User registered successfully!")
        self.clear_widgets()
        self.login_screen()

    def login(self):
        username = self.username_entry.get()
        master_password = self.password_entry.get()

        if not username or not master_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        self.user_id = authenticate_user(self.conn, username, master_password)
        if self.user_id:
            self.key = generate_key(master_password)
            self.main_screen()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def main_screen(self):
        self.clear_widgets()

       
        header_label = tk.Label(self, text="Password Manager", font=('Helvetica', 24), bg='#4CAF50', fg='white', padx=10, pady=10)
        header_label.pack(fill=tk.X)

       
        button_frame = tk.Frame(self, bg='#f0f0f0')
        button_frame.pack(pady=20)

        add_button = tk.Button(button_frame, text="Add Password", command=self.add_password_screen, font=('Arial', 14))
        add_button.grid(row=0, column=0, padx=10, pady=10)

        get_button = tk.Button(button_frame, text="Get Password", command=self.get_password_screen, font=('Arial', 14))
        get_button.grid(row=0, column=1, padx=10, pady=10)

        view_button = tk.Button(button_frame, text="View All Passwords", command=self.view_all_passwords_screen, font=('Arial', 14))
        view_button.grid(row=0, column=2, padx=10, pady=10)

        change_password_button = tk.Button(button_frame, text="Change Master Password", command=self.change_master_password_screen, font=('Arial', 14))
        change_password_button.grid(row=0, column=3, padx=10, pady=10)

        logout_button = tk.Button(button_frame, text="Logout", command=self.logout, font=('Arial', 14), bg='red', fg='white')
        logout_button.grid(row=0, column=4, padx=10, pady=10)

     
        footer_label = tk.Label(self, text="Logged in as: " + self.username_entry.get(), bg='#333', fg='white', font=('Arial', 10), anchor=tk.W)
        footer_label.pack(fill=tk.X, side=tk.BOTTOM, ipady=5)

    def add_password_screen(self):
        self.clear_widgets()

      
        header_label = tk.Label(self, text="Add Password", font=('Helvetica', 18), bg='#4CAF50', fg='white', padx=10, pady=10)
        header_label.pack(fill=tk.X)

        
        add_frame = tk.Frame(self, bg='#f0f0f0')
        add_frame.pack(pady=50)

        service_label = tk.Label(add_frame, text="Service:", bg='#f0f0f0', font=('Arial', 14))
        service_label.grid(row=0, column=0, padx=10, pady=5)
        self.service_entry = tk.Entry(add_frame, font=('Arial', 14))
        self.service_entry.grid(row=0, column=1, padx=10, pady=5)

        username_label = tk.Label(add_frame, text="Username:", bg='#f0f0f0', font=('Arial', 14))
        username_label.grid(row=1, column=0, padx=10, pady=5)
        self.username_entry = tk.Entry(add_frame, font=('Arial', 14))
        self.username_entry.grid(row=1, column=1, padx=10, pady=5)

        password_label = tk.Label(add_frame, text="Password:", bg='#f0f0f0', font=('Arial', 14))
        password_label.grid(row=2, column=0, padx=10, pady=5)
        self.password_entry = tk.Entry(add_frame, show='*', font=('Arial', 14))
        self.password_entry.grid(row=2, column=1, padx=10, pady=5)

        generate_button = tk.Button(add_frame, text="Generate Password", command=self.generate_password, font=('Arial', 12))
        generate_button.grid(row=2, column=2, padx=10, pady=5)

        add_button = tk.Button(add_frame, text="Add", command=self.add_password, bg='#2196F3', fg='white', font=('Arial', 14))
        add_button.grid(row=3, column=0, columnspan=2, pady=10)

        back_button = tk.Button(add_frame, text="Back", command=self.main_screen, bg='#333', fg='white', font=('Arial', 14))
        back_button.grid(row=3, column=2, pady=10)

        
        footer_label = tk.Label(self, text="Logged in as: " + self.username_entry.get(), bg='#333', fg='white', font=('Arial', 10), anchor=tk.W)
        footer_label.pack(fill=tk.X, side=tk.BOTTOM, ipady=5)

    def generate_password(self):
        password = generate_random_password()
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        strength = check_password_strength(password)
        messagebox.showinfo("Password Generated", f"Generated Password: {password}\nStrength: {strength}")

    def add_password(self):
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not service or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        add_password(self.conn, self.user_id, self.key, service, username, password)
        messagebox.showinfo("Success", "Password added successfully!")
        self.clear_widgets()
        self.main_screen()

    def get_password_screen(self):
        self.clear_widgets()

   
        header_label = tk.Label(self, text="Get Password", font=('Helvetica', 18), bg='#4CAF50', fg='white', padx=10, pady=10)
        header_label.pack(fill=tk.X)

  
        get_frame = tk.Frame(self, bg='#f0f0f0')
        get_frame.pack(pady=50)

        service_label = tk.Label(get_frame, text="Service:", bg='#f0f0f0', font=('Arial', 14))
        service_label.grid(row=0, column=0, padx=10, pady=5)
        self.service_entry = tk.Entry(get_frame, font=('Arial', 14))
        self.service_entry.grid(row=0, column=1, padx=10, pady=5)

        get_button = tk.Button(get_frame, text="Get Password", command=self.get_password, font=('Arial', 14))
        get_button.grid(row=1, column=0, columnspan=2, pady=10)

        back_button = tk.Button(get_frame, text="Back", command=self.main_screen, font=('Arial', 14), bg='#333', fg='white')
        back_button.grid(row=2, column=0, columnspan=2, pady=10)

      
        footer_label = tk.Label(self, text="Logged in as: " + self.username_entry.get(), bg='#333', fg='white', font=('Arial', 10), anchor=tk.W)
        footer_label.pack(fill=tk.X, side=tk.BOTTOM, ipady=5)

    def get_password(self):
        service = self.service_entry.get()
        if not service:
            messagebox.showerror("Error", "Please enter a service name")
            return

        result = get_password(self.conn, self.user_id, self.key, service)
        if result:
            username, password = result
            messagebox.showinfo("Password Retrieved", f"Username: {username}\nPassword: {password}")
        else:
            messagebox.showerror("Error", "No password found for this service.")

    def view_all_passwords_screen(self):
        self.clear_widgets()

       
        header_label = tk.Label(self, text="View All Passwords", font=('Helvetica', 18), bg='#4CAF50', fg='white', padx=10, pady=10)
        header_label.pack(fill=tk.X)

    
        passwords_frame = tk.Frame(self, bg='#f0f0f0')
        passwords_frame.pack(pady=20, padx=10)

        self.tree = ttk.Treeview(passwords_frame, columns=('Service', 'Username', 'Password'), show='headings')
        self.tree.heading('Service', text='Service')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Password', text='Password')
        self.tree.pack(fill=tk.BOTH, expand=True)

  
        back_button = tk.Button(self, text="Back", command=self.main_screen, font=('Arial', 14), bg='#333', fg='white')
        back_button.pack(pady=10)

  
        cur = self.conn.execute('SELECT service, username, password FROM passwords WHERE user_id = ?', (self.user_id,))
        for row in cur.fetchall():
            fernet = Fernet(self.key)
            service, username, encrypted_password = row
            decrypted_password = fernet.decrypt(encrypted_password).decode('utf-8')
            self.tree.insert('', tk.END, values=(service, username, decrypted_password))

        
        footer_label = tk.Label(self, text="Logged in as: " + self.username_entry.get(), bg='#333', fg='white', font=('Arial', 10), anchor=tk.W)
        footer_label.pack(fill=tk.X, side=tk.BOTTOM, ipady=5)

    def delete_password_screen(self):
        self.clear_widgets()

    
        header_label = tk.Label(self, text="Delete Password", font=('Helvetica', 18), bg='#4CAF50', fg='white', padx=10, pady=10)
        header_label.pack(fill=tk.X)

     
        delete_frame = tk.Frame(self, bg='#f0f0f0')
        delete_frame.pack(pady=50)

        service_label = tk.Label(delete_frame, text="Service:", bg='#f0f0f0', font=('Arial', 14))
        service_label.grid(row=0, column=0, padx=10, pady=5)
        self.service_entry = tk.Entry(delete_frame, font=('Arial', 14))
        self.service_entry.grid(row=0, column=1, padx=10, pady=5)

        delete_button = tk.Button(delete_frame, text="Delete Password", command=self.delete_password_action, font=('Arial', 14), bg='#FF5722', fg='white')
        delete_button.grid(row=1, column=0, columnspan=2, pady=10)

        back_button = tk.Button(delete_frame, text="Back", command=self.main_screen, font=('Arial', 14), bg='#333', fg='white')
        back_button.grid(row=2, column=0, columnspan=2, pady=10)

        
        footer_label = tk.Label(self, text="Logged in as: " + self.username_entry.get(), bg='#333', fg='white', font=('Arial', 10), anchor=tk.W)
        footer_label.pack(fill=tk.X, side=tk.BOTTOM, ipady=5)

    def delete_password_action(self):
        service = self.service_entry.get()
        if not service:
            messagebox.showerror("Error", "Please enter a service name")
            return

        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the password for {service}?"):
            delete_password(self.conn, self.user_id, service)
            messagebox.showinfo("Success", f"Password for {service} deleted successfully")
            self.clear_widgets()
            self.main_screen()

    def change_master_password_screen(self):
        self.clear_widgets()

      
        header_label = tk.Label(self, text="Change Master Password", font=('Helvetica', 18), bg='#4CAF50', fg='white', padx=10, pady=10)
        header_label.pack(fill=tk.X)

       
        change_frame = tk.Frame(self, bg='#f0f0f0')
        change_frame.pack(pady=50)

        current_password_label = tk.Label(change_frame, text="Current Master Password:", bg='#f0f0f0', font=('Arial', 14))
        current_password_label.grid(row=0, column=0, padx=10, pady=5)
        self.current_password_entry = tk.Entry(change_frame, show='*', font=('Arial', 14))
        self.current_password_entry.grid(row=0, column=1, padx=10, pady=5)

        new_password_label = tk.Label(change_frame, text="New Master Password:", bg='#f0f0f0', font=('Arial', 14))
        new_password_label.grid(row=1, column=0, padx=10, pady=5)
        self.new_password_entry = tk.Entry(change_frame, show='*', font=('Arial', 14))
        self.new_password_entry.grid(row=1, column=1, padx=10, pady=5)

        change_button = tk.Button(change_frame, text="Change Master Password", command=self.change_master_password_action, bg='#4CAF50', fg='white', font=('Arial', 14))
        change_button.grid(row=2, column=0, columnspan=2, pady=10)

        back_button = tk.Button(change_frame, text="Back", command=self.main_screen, bg='#333', fg='white', font=('Arial', 14))
        back_button.grid(row=3, column=0, columnspan=2, pady=10)

        
        footer_label = tk.Label(self, text="Logged in as: " + self.username_entry.get(), bg='#333', fg='white', font=('Arial', 10), anchor=tk.W)
        footer_label.pack(fill=tk.X, side=tk.BOTTOM, ipady=5)

    def change_master_password_action(self):
        current_password = self.current_password_entry.get()
        new_password = self.new_password_entry.get()

        if not current_password or not new_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        
        current_password_hash = hashlib.sha256(current_password.encode('utf-8')).hexdigest()
        stored_password_hash = self.conn.execute('SELECT master_password_hash FROM users WHERE id = ?', (self.user_id,)).fetchone()[0]

        if current_password_hash != stored_password_hash:
            messagebox.showerror("Error", "Current password is incorrect")
            return

        
        new_password_hash = hashlib.sha256(new_password.encode('utf-8')).hexdigest()
        self.conn.execute('UPDATE users SET master_password_hash = ? WHERE id = ?', (new_password_hash, self.user_id))
        self.conn.commit()
        messagebox.showinfo("Success", "Master password changed successfully")
        self.main_screen()

    def clear_widgets(self):
        for widget in self.winfo_children():
            widget.destroy()

    def run(self):
        self.mainloop()

if __name__ == '__main__':
    app = PasswordManagerApp()
    app.run()
