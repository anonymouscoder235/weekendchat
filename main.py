import streamlit as st
from datetime import datetime
import json
import os
from streamlit_autorefresh import st_autorefresh
import hashlib
import hmac

# Configure page settings
st.set_page_config(
    page_title="Secure Chat",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for clean, spacious UI
clean_style = """
<style>
    /* Hide all default Streamlit UI elements */
    
    /* Main content area styling - reduced padding */
    .main .block-container {
        padding-top: 1rem;
        padding-bottom: 1rem;
        padding-left: 2rem;
        padding-right: 2rem;
    }
    
    /* Sidebar styling that works in both light and dark modes */
    [data-testid="stSidebar"] {
        padding: 1rem 1rem;
    }
    
    /* Dark mode sidebar background */
    [theme="dark"] [data-testid="stSidebar"] {
        background-color: #1a1a1a;
    }
    
    /* Light mode sidebar background */
    [theme="light"] [data-testid="stSidebar"] {
        background-color: #f8f9fa;
    }
    
    /* Chat message styling */
    .message {
        padding: 0.5rem 0.75rem;
        margin: 0.25rem 0;
        border-radius: 0.5rem;
        max-width: 70%;
        word-wrap: break-word;
        line-height: 1.4;
    }
    
    .user-message {
        background-color: #007bff;
        color: white;
        margin-left: auto;
        border-bottom-right-radius: 0.1rem;
    }
    
    .other-message {
        background-color: #e9ecef;
        color: black;
        margin-right: auto;
        border-bottom-left-radius: 0.1rem;
    }
    
    /* Dark mode adjustments for other-message */
    [theme="dark"] .other-message {
        background-color: #2d3741;
        color: white;
    }
    
    /* Input area styling */
    .stTextArea textarea {
        min-height: 80px;
        border-radius: 0.5rem;
        padding: 0.75rem;
    }
    
    /* Button styling that works in both modes */
    .stButton button {
        width: 100%;
        border-radius: 0.5rem;
        padding: 0.5rem;
        transition: all 0.2s;
        border: 1px solid transparent;
    }
    
    /* Dark mode button adjustments */
    [theme="dark"] .stButton button {
        background-color: #2d3741;
        color: white;
        border-color: #4a5568;
    }
    
    /* Active user button styling */
    .user-button {
        width: 100%;
        text-align: left;
        padding: 0.5rem;
        border-radius: 0.5rem;
        margin-bottom: 0.25rem;
        transition: all 0.2s;
    }
    
    /* Dark mode active user button */
    [theme="dark"] .user-button {
        background-color: #2d3741;
        color: white;
        border: 1px solid #4a5568;
    }
    
    /* Light mode active user button */
    [theme="light"] .user-button {
        background-color: #ffffff;
        color: black;
        border: 1px solid #e9ecef;
    }
</style>
"""

# Apply CSS
st.markdown(clean_style, unsafe_allow_html=True)

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

# Password hashing functions (unchanged)
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

# User registration (unchanged)
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

# Update user presence (unchanged)
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

# User authentication (unchanged)
def authenticate_user(username, password):
    with open(USER_FILE, "r") as f:
        users = json.load(f)
    
    if username not in users:
        return False
    
    stored_password = bytes.fromhex(users[username]['password'])
    return verify_password(stored_password, password)

# Load chat data (unchanged)
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

# Save chat data (unchanged)
def save_chat_data(data):
    with open(CHAT_FILE, "w") as f:
        json.dump(data, f)

# Get or create session (unchanged)
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

# Add a new message (unchanged)
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

# Check unread messages (unchanged)
def check_unread_messages(username):
    data = load_chat_data()
    for session_id, session in data.get("sessions", {}).items():
        if username in session["participants"] and session["unread"].get(username, False):
            other_user = session["participants"][0] if session["participants"][1] == username else session["participants"][1]
            return other_user
    return None

# Improved Authentication Page
def auth_page():
    st.title("Secure Chat")
    st.markdown('<div class="spacer-md"></div>', unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        st.subheader("Welcome back")
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            st.markdown('<div class="spacer-sm"></div>', unsafe_allow_html=True)
            if st.form_submit_button("Login", use_container_width=True):
                if authenticate_user(username, password):
                    update_user_presence(username)
                    st.session_state.username = username
                    st.session_state.authenticated = True
                    st.rerun()
                else:
                    st.error("Invalid username or password")
    
    with tab2:
        st.subheader("Create an account")
        with st.form("register_form"):
            username = st.text_input("Username", key="register_username")
            password = st.text_input("Password", type="password", key="register_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
            st.markdown('<div class="spacer-sm"></div>', unsafe_allow_html=True)
            if st.form_submit_button("Register", use_container_width=True):
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

# Improved Main App
def main_app():
    # Update user presence on every refresh
    if "username" in st.session_state:
        update_user_presence(st.session_state.username)
    
    # Check for unread messages
    username = st.session_state.username
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
        st.subheader(f"Hello, {username}!")
        st.markdown('<div class="spacer-sm"></div>', unsafe_allow_html=True)
        
        # Active users section
        st.markdown("**Online Users**")
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
                active_users.append(user)
        
        if not active_users:
            st.caption("No other users online")
        else:
            for user in active_users:
                session_id = get_session(username, user)
                unread = data["sessions"][session_id]["unread"].get(username, False)
                if st.button(f"{user}{' 🔔' if unread else ''}", key=f"user_{user}", use_container_width=True):
                    st.session_state.current_chat = user
                    # Mark as read when opening
                    data["sessions"][session_id]["unread"][username] = False
                    save_chat_data(data)
                    st.rerun()
        
        st.markdown('<div class="spacer-md"></div>', unsafe_allow_html=True)
        
        if "current_chat" in st.session_state:
            if st.button("Leave Chat", use_container_width=True):
                del st.session_state.current_chat
                st.rerun()
        
        if st.button("Sign Out", use_container_width=True):
            del st.session_state.username
            del st.session_state.authenticated
            if "current_chat" in st.session_state:
                del st.session_state.current_chat
            st.rerun()
    
    # Main chat area
    if "current_chat" not in st.session_state:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            #st.markdown('<div class="spacer-lg"></div>', unsafe_allow_html=True)
            st.image("https://cdn-icons-png.flaticon.com/512/2462/2462719.png", width=150)
            #st.markdown('<div class="spacer-sm"></div>', unsafe_allow_html=True)
            st.subheader("Select a user to start chatting")
            st.caption("Choose someone from the sidebar to begin your conversation")
        st.stop()
    
    # Chat interface
    other_user = st.session_state.current_chat
    session_id = get_session(username, other_user)
    
    st.subheader(f"Chat with {other_user}")
    st.markdown('<div class="spacer-sm"></div>', unsafe_allow_html=True)
    
    # Display messages
    data = load_chat_data()
    messages = data["sessions"][session_id]["messages"]
    
    # In the message display section, use this format:
    for msg in messages:
        
     timestamp = datetime.strptime(msg["timestamp"], "%Y-%m-%d %H:%M:%S").strftime("%H:%M")
     if msg["sender"] == username:
        st.markdown(f"""
        <div class="message user-message">
            <div style="font-size: 0.75rem; opacity: 0.8;">{timestamp}</div>
            {msg["message"]}
        </div>
        """, unsafe_allow_html=True)
     else:
        st.markdown(f"""
        <div class="message other-message">
            <div style="font-size: 0.75rem; opacity: 0.8;">{msg["sender"]} • {timestamp}</div>
            {msg["message"]}
        </div>
        """, unsafe_allow_html=True)
    st.markdown('<div class="spacer-md"></div>', unsafe_allow_html=True)
    
    # Message input
    with st.form("message_form", clear_on_submit=True):
        message = st.text_area("Type your message", height=30, key=f"msg_{session_id}", 
                             placeholder="Write your message here...", label_visibility="collapsed")
        col1, col2 = st.columns([3, 1])
        with col2:
            if st.form_submit_button("Send", use_container_width=True):
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
