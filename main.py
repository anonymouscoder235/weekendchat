import streamlit as st
from datetime import datetime
import json
import os
from streamlit_autorefresh import st_autorefresh
import hashlib
import hmac

# Disable Streamlit default UI elements
st.set_page_config(
    page_title="Secure Chat",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS to hide all unnecessary bars
hide_streamlit_style = """
<style>
    footer {visibility: hidden;}
    
    /* Dynamic black bar (5% of screen height) */
    .footer-overlay {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        height: 5vh;
        background-color: #000000;
        z-index: 9999;
    }
    
    /* Adjust main container to prevent content hiding */
    .main .block-container {
        padding-bottom: 6vh !important;
    }
    /* Hide header */
    [data-testid="stToolbarActions"] {
        display: none !important;
    }
    div._profileContainer_gzau3_53 {
        display: none !important;
    }
    
    /* Hide footer */
    footer[data-testid="stFooter"] {
        display: none !important;
    }
    
    /* Hide status widget */
    iframe[title="Streamlit Cloud Status"] {
        display: none !important;
    }
    
    /* Hide 'Manage app' button */
    button[data-testid="manage-app-button"] {
        display: none !important;
    }
    
    /* Adjust main container padding */
    .main .block-container {
        padding-top: 0rem;
        padding-bottom: 0rem;
    }
    
    /* Hide hamburger menu */
    #MainMenu {
        visibility: hidden;
    }
    
    /* Hide Streamlit logo in tab */
    [data-testid="stAppViewContainer"] > div:first-child {
        display: none;
    }

    [class="_profileContainer_gzau3_53"] > div:first-child {
        display: none !important;
    }
    
</style>
"""

# Apply CSS
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# Configuration
CHAT_FILE = "private_chat_data.json"
USER_FILE = "user_credentials.json"
REFRESH_INTERVAL = 2000  # milliseconds

# Initialize data files if they don't exist
if not os.path.exists(CHAT_FILE):
    with open(CHAT_FILE, "w") as f:
        json.dump({"sessions": {}, "users": {}}, f)

if not os.path.exists(USER_FILE):
    with open(USER_FILE, "w") as f:
        json.dump({}, f)

# Auto-refresh the app
st_autorefresh(interval=REFRESH_INTERVAL, limit=None, key="chat_refresh")

# Password hashing
def hash_password(password):
    """Hash a password for storing."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return salt + key

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:32]
    stored_key = stored_password[32:]
    new_key = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        salt,
        100000
    )
    return hmac.compare_digest(stored_key, new_key)

# User registration
def register_user(username, password):
    with open(USER_FILE, "r") as f:
        users = json.load(f)
    
    if username in users:
        return False  # User already exists
    
    users[username] = {
        'password': hash_password(password).hex(),
        'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    with open(USER_FILE, "w") as f:
        json.dump(users, f)
    
    # Create presence record in chat data
    update_user_presence(username)
    
    return True

# Update user presence
def update_user_presence(username):
    """Update or create user presence record"""
    data = load_chat_data()
    
    # Initialize users dictionary if it doesn't exist
    if "users" not in data:
        data["users"] = {}
    
    # Create or update user record
    if username not in data["users"]:
        data["users"][username] = {}
    
    # Update last seen time
    data["users"][username]["last_seen"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    save_chat_data(data)

# User authentication
def authenticate_user(username, password):
    with open(USER_FILE, "r") as f:
        users = json.load(f)
    
    if username not in users:
        return False
    
    stored_password = bytes.fromhex(users[username]['password'])
    return verify_password(stored_password, password)

# Load chat data with migration for older versions
def load_chat_data():
    with open(CHAT_FILE, "r") as f:
        data = json.load(f)
    
    # Migration: Add 'unread' field to existing sessions if missing
    for session_id, session in data.get("sessions", {}).items():
        if "unread" not in session:
            session["unread"] = {
                session["participants"][0]: False,
                session["participants"][1]: False
            }
    
    # Ensure users dictionary exists
    if "users" not in data:
        data["users"] = {}
    
    return data

# Save chat data
def save_chat_data(data):
    with open(CHAT_FILE, "w") as f:
        json.dump(data, f)

# Get or create session between two users
def get_session(user1, user2):
    session_id = f"{min(user1, user2)}_{max(user1, user2)}"
    data = load_chat_data()
    
    if session_id not in data["sessions"]:
        data["sessions"][session_id] = {
            "participants": [user1, user2],
            "messages": [],
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "unread": {user1: False, user2: False}
        }
        save_chat_data(data)
    elif "unread" not in data["sessions"][session_id]:
        # Ensure unread exists (backward compatibility)
        data["sessions"][session_id]["unread"] = {
            user1: False,
            user2: False
        }
        save_chat_data(data)
    
    return session_id

# Add a new message to a session
def add_message(session_id, sender, message):
    data = load_chat_data()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Mark as unread for the recipient
    participants = data["sessions"][session_id]["participants"]
    recipient = participants[0] if participants[1] == sender else participants[1]
    data["sessions"][session_id]["unread"][recipient] = True
    
    data["sessions"][session_id]["messages"].append({
        "sender": sender,
        "message": message,
        "timestamp": timestamp
    })
    
    # Update sender's presence
    update_user_presence(sender)
    
    save_chat_data(data)

# Check if user has any unread messages
def check_unread_messages(username):
    data = load_chat_data()
    for session_id, session in data.get("sessions", {}).items():
        if username in session["participants"] and session["unread"].get(username, False):
            other_user = session["participants"][0] if session["participants"][1] == username else session["participants"][1]
            return other_user
    return None

# Authentication page
def auth_page():
    st.title("🔒 Secure Chat Authentication")
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            if st.form_submit_button("Login"):
                if authenticate_user(username, password):
                    # Update user presence
                    update_user_presence(username)
                    
                    st.session_state.username = username
                    st.session_state.authenticated = True
                    st.rerun()
                else:
                    st.error("Invalid username or password")
    
    with tab2:
        with st.form("register_form"):
            username = st.text_input("Username", key="register_username")
            password = st.text_input("Password", type="password", key="register_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
            if st.form_submit_button("Register"):
                if password != confirm_password:
                    st.error("Passwords do not match")
                elif len(username) < 3:
                    st.error("Username must be at least 3 characters")
                elif len(password) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    if register_user(username, password):
                        st.success("Registration successful! Please login.")
                    else:
                        st.error("Username already exists")

# Main chat app
def main_app():
    # Update user presence on every refresh
    if "username" in st.session_state:
        update_user_presence(st.session_state.username)
    
    st.title("🔒 Private Chat Sessions")
    
    # User management
    username = st.session_state.username
    
    # Check for unread messages and automatically open that chat
    if "current_chat" not in st.session_state:
        unread_from = check_unread_messages(username)
        if unread_from:
            st.session_state.current_chat = unread_from
            # Mark as read
            data = load_chat_data()
            session_id = get_session(username, unread_from)
            data["sessions"][session_id]["unread"][username] = False
            save_chat_data(data)
            st.rerun()
    
    # Sidebar with user info and controls
    with st.sidebar:
        st.subheader(f"Welcome, {username}!")
        
        # Show active users (excluding current user)
        data = load_chat_data()
        active_users = []
        for user, info in data.get("users", {}).items():
            if user == username:
                continue
            last_seen_str = info.get("last_seen", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            try:
                last_seen = datetime.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S")
                if (datetime.now() - last_seen).seconds < 300:  # 5 minutes
                    active_users.append(user)
            except:
                # If there's an error parsing timestamp, include user anyway
                active_users.append(user)
        
        st.write("**Start a private chat with:**")
        if not active_users:
            st.write("No other users online")
        else:
            for user in active_users:
                session_id = get_session(username, user)
                unread = data["sessions"][session_id]["unread"].get(username, False)
                button_label = f"💬 {user}" + (" 🔔" if unread else "")
                if st.button(button_label):
                    st.session_state.current_chat = user
                    # Mark as read when opening
                    data["sessions"][session_id]["unread"][username] = False
                    save_chat_data(data)
                    st.rerun()
        
        if "current_chat" in st.session_state:
            if st.button("Leave Current Chat"):
                del st.session_state.current_chat
                st.rerun()
        
        if st.button("Sign Out"):
            del st.session_state.username
            del st.session_state.authenticated
            if "current_chat" in st.session_state:
                del st.session_state.current_chat
            st.rerun()
    
    # Chat interface
    if "current_chat" not in st.session_state:
        st.info("Select a user from the sidebar to start chatting")
        st.stop()
    
    other_user = st.session_state.current_chat
    session_id = get_session(username, other_user)
    
    st.subheader(f"Private chat with {other_user}")
    
    # Display messages
    data = load_chat_data()
    messages = data["sessions"][session_id]["messages"]
    
    for msg in messages:
        timestamp = msg["timestamp"]
        if msg["sender"] == username:
            st.markdown(f"""
            <div style="background-color: #0068c9; color: white; padding: 10px; border-radius: 10px 0px 10px 10px; margin: 5px 0; margin-left: 20%; text-align: right;">
                <strong>You ({timestamp}):</strong> {msg["message"]}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background-color: #2d3741; color: white; padding: 10px; border-radius: 0px 10px 10px 10px; margin: 5px 0; margin-right: 20%;">
                <strong>{msg["sender"]} ({timestamp}):</strong> {msg["message"]}
            </div>
            """, unsafe_allow_html=True)
    
    # Send message form
    with st.form("message_form"):
        message = st.text_area("Type your private message", height=100, key=f"msg_{session_id}")
        if st.form_submit_button("Send"):
            if message.strip():
                add_message(session_id, username, message.strip())
                st.rerun()

# Main app flow
def main():
    if not hasattr(st.session_state, 'authenticated') or not st.session_state.authenticated:
        auth_page()
    else:
        main_app()

if __name__ == "__main__":
    main()
