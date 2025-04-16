import streamlit as st
import os
import json
import base64
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
from base64 import urlsafe_b64encode

# ----------------- Constants -----------------
USER_DB = "users.json"
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

# ----------------- Helper Functions -----------------
def load_users():
    if not os.path.exists(USER_DB):
        return {}
    with open(USER_DB, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def derive_key(password: str, salt: bytes) -> bytes:
    key = pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return urlsafe_b64encode(key)

def encrypt_data(data: str, password: str) -> tuple:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return base64.b64encode(salt).decode(), encrypted.decode()

def decrypt_data(encrypted: str, password: str, salt_b64: str) -> str:
    try:
        salt = base64.b64decode(salt_b64.encode())
        key = derive_key(password, salt)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted.encode()).decode()
    except Exception as e:
        return f"❌ Error: {e}"

def save_user_data(username, salt, encrypted_data):
    filepath = DATA_DIR / f"{username}.json"
    with open(filepath, "w") as f:
        json.dump({"salt": salt, "data": encrypted_data}, f)

def load_user_data(username):
    filepath = DATA_DIR / f"{username}.json"
    if not filepath.exists():
        return None
    with open(filepath, "r") as f:
        return json.load(f)

# ----------------- Session State -----------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.username = ""

# ----------------- Navigation -----------------
st.sidebar.title("🔐 Menu")
choice = st.sidebar.radio("Go to", ["Home", "Register", "Login", "Store Data", "Retrieve Data"])

# ----------------- Pages -----------------

# Home
if choice == "Home":
    st.title("🔐 Secure Data Encryption System")
    st.markdown("""
    Welcome! This app lets you:
    - Register & log in securely
    - Store encrypted personal data
    - Retrieve it anytime with your password
    
    Built with 🔒 Fernet + PBKDF2 and ☁️ local JSON storage.
    """)

# Register
elif choice == "Register":
    st.title("📝 Register")
    username = st.text_input("Choose a username")
    password = st.text_input("Choose a password", type="password")

    if st.button("Register"):
        users = load_users()
        if username in users:
            st.warning("Username already exists. Try another.")
        else:
            users[username] = hash_password(password)
            save_users(users)
            st.success("Registered successfully! Now log in.")

# Login
elif choice == "Login":
    st.title("🔑 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        users = load_users()
        if username in users and users[username] == hash_password(password):
            st.session_state.authenticated = True
            st.session_state.username = username
            st.success("Login successful!")
        else:
            st.error("Invalid credentials.")

# Store Data
elif choice == "Store Data":
    st.title("📥 Store Encrypted Data")
    if st.session_state.authenticated:
        data = st.text_area("Enter your data to encrypt")
        password = st.text_input("Re-enter your password", type="password")

        if st.button("Encrypt & Save"):
            users = load_users()
            if users.get(st.session_state.username) == hash_password(password):
                salt, encrypted = encrypt_data(data, password)
                save_user_data(st.session_state.username, salt, encrypted)
                st.success("Data encrypted and saved successfully.")
            else:
                st.error("Password incorrect.")
    else:
        st.warning("Please log in first.")

# Retrieve Data
elif choice == "Retrieve Data":
    st.title("📤 Retrieve Your Data")
    if st.session_state.authenticated:
        password = st.text_input("Enter your password", type="password")

        if st.button("Decrypt & Show"):
            users = load_users()
            if users.get(st.session_state.username) == hash_password(password):
                saved = load_user_data(st.session_state.username)
                if saved:
                    result = decrypt_data(saved["data"], password, saved["salt"])
                    if result.startswith("❌"):
                        st.error(result)
                    else:
                        st.success("Data decrypted:")
                        st.code(result, language="text")
                else:
                    st.info("No saved data found.")
            else:
                st.error("Password incorrect.")
    else:
        st.warning("Please log in first.")
