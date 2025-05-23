###### AUTH LOGIC (auth.py) ######

from __imports__ import bcr
import csv
import os
# Define the CSV file path (in the same directory as auth.py)
CSV_FILE = os.path.join(os.path.dirname(__file__), "users.csv")

# Global user store; keys are usernames and values are the hashed password (as bytes)
users = {}

# load CSV on startup to verify user existence
def load_users():
    """
    Load users from the CSV file and update the global `users` dictionary.
    Each CSV row should contain: username, password_hash (stored as utf-8 string)
    """
    global users
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) >= 2:
                    username, password_hash_str = row[0], row[1]
                    # Convert the stored hash string back to bytes.
                    users[username] = password_hash_str.encode('utf-8')
    else:
        # If the CSV doesn't exist, create an empty file.
        with open(CSV_FILE, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # No initial rows; the file will be empty.
        users.clear()

# save username(in test) and password(hashed and encrypted) to csv/ db
def save_user_to_csv(username, password_hash_bytes):
    """
    Append a new user record to the CSV file.
    The hashed password is stored as its UTF-8 decoded string.
    """
    with open(CSV_FILE, 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([username, password_hash_bytes.decode('utf-8')])

# initialize admin user
def init_default_users():
    """
    Load users from CSV.
    If the default 'admin' user doesn't exist yet, create one.
    """
    load_users()
    if "admin" not in users:
        default_username = "admin"
        default_password = "mypassword"
        hashed = bcr.hashpw(default_password.encode(), bcr.gensalt())
        users[default_username] = hashed
        save_user_to_csv(default_username, hashed)

# authentication logiv
def authenticate(username_input, password_input):
    if username_input in users:
        return bcr.checkpw(password_input.encode(), users[username_input])
    return False

# register user logic
def register_user(username, password):
    if username in users:
        return False, "User already exists"
    hashed = bcr.hashpw(password.encode(), bcr.gensalt())
    users[username] = hashed
    save_user_to_csv(username, hashed)
    return True, "User created successfully"

# Initialize default user upon module load.
init_default_users()


###### LOGIN LOGIC (login.py) #######

# login.py
from __imports__ import CTk, bcr
import auth
import ui
# from gui import run_main_app

# configure window
CTk.set_appearance_mode("Dark")
CTk.set_default_color_theme("blue")

# registration window for new user
def show_registration():
    reg_window = CTk.CTk()
    reg_window.geometry("400x300")
    reg_window.title("Register New User")
    CTk.CTkLabel(reg_window, text="New Username:").pack(pady=(20,5))
    new_username_entry = CTk.CTkEntry(reg_window)
    new_username_entry.pack(pady=5)
    CTk.CTkLabel(reg_window, text="New Password:").pack(pady=(10,5))
    new_password_entry = CTk.CTkEntry(reg_window, show="*")
    new_password_entry.pack(pady=5)
    # reg expression and input validation
    def on_register():
        username = new_username_entry.get().strip()
        password = new_password_entry.get().strip()
        if not username or not password:
            CTk.CTkLabel(reg_window, text="Please fill in all fields", text_color="red").pack(pady=5)
            return
        success, message = auth.register_user(username, password)
        CTk.CTkLabel(reg_window, text=message, text_color=("green" if success else "red")).pack(pady=5)
        # saving values, and destroy window
        if success:
            fs.writeFile
            reg_window.after(1500, reg_window.destroy)
    # resitration window mainloop and pack
    CTk.CTkButton(reg_window, text="Register", command=on_register).pack(pady=20)
    reg_window.mainloop()

# login logic
def show_login():
    login_window = CTk.CTk()
    login_window.geometry("400x300")
    login_window.title("Login")
    # u-name input and pack
    CTk.CTkLabel(login_window, text="Username:").pack(pady=(20, 5))
    username_entry = CTk.CTkEntry(login_window)
    username_entry.pack(pady=5)
    # p-word input and pack
    CTk.CTkLabel(login_window, text="Password:").pack(pady=(10, 5))
    password_entry = CTk.CTkEntry(login_window, show="*")
    password_entry.pack(pady=5)
    # authentication validation into an if else to either proceed to main window or throw error.
    def on_login():
        username = username_entry.get()
        password = password_entry.get()
        # auth == true
        if auth.authenticate(username, password):
            login_window.destroy()  # close the login window
            # configure this as needed
            run_main_app()          # open the main UI
        # auth = false
        else:
            CTk.CTkLabel(login_window, text="Invalid username or password", text_color="red").pack(pady=10)
    # ui buttons for event triggering
    CTk.CTkButton(login_window, text="Login", command=on_login).pack(pady=20)
    # Button to open the registration window
    CTk.CTkButton(login_window, text="Create New User", command=show_registration).pack(pady=5)
    # login window mainloop
    login_window.mainloop()
# execution and exit function
if __name__ == "__main__":
    show_login()
