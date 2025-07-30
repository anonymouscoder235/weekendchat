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

# Custom CSS for clean UI
clean_style = """
<style>
    /* Hide default UI elements */
    
    /* Main content styling */
    .main .block-container {
        padding-top: 1rem;
        padding-bottom: 1rem;
        padding-left: 2rem;
        padding-right: 2rem;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        padding: 1rem 1rem;
    }
    
    /* Dark mode support */
    [theme="dark"] [data-testid="stSidebar"] {
        background-color: #1a1a1a;
    }
    [theme="light"] [data-testid="stSidebar"] {
        background-color: #f8f9fa;
    }
    
    /* Message bubbles */
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
    }
    .other-message {
        background-color: #e9ecef;
        color: black;
        margin-right: auto;
    }
    [theme="dark"] .other-message {
        background-color: #2d3741;
        color: white;
    }
    
    /* Timestamp styling */
    .timestamp {
        font-size: 0.75rem;
        opacity: 0.8;
    }
    
    /* Input area */
    .stTextArea textarea {
        min-height: 80px;
        border-radius: 0.5rem;
        padding: 0.75rem;
    }
    
    /* Buttons */
    .stButton button {
        width: 100%;
        border-radius: 0.5rem;
        padding: 0.5rem;
    }
    [theme="dark"] .stButton button {
        background-color: #2d3741;
        color: white;
    }
</style>
"""

# JavaScript for timezone conversion
timezone_js = """
<script>
function updateTimestamps() {
    document.querySelectorAll('[data-utc]').forEach(el => {
        const utcTime = el.getAttribute('data-utc');
        try {
            const timeStr = new Date(utcTime).toLocaleTimeString([], 
                {hour: '2-digit', minute:'2-digit', hour12: false});
            if (el.textContent.includes('•')) {
                const sender = el.textContent.split('•')[0].trim();
                el.textContent = `${sender} • ${timeStr}`;
            } else {
                el.textContent = timeStr;
            }
        } catch(e) {
            console.error('Timestamp error:', e);
        }
    });
}

// Run on load and after updates
document.addEventListener('DOMContentLoaded', updateTimestamps);
document.addEventListener('streamlit:render', updateTimestamps);
</script>
"""

# Apply CSS
st.markdown(clean_style, unsafe_allow_html=True)

# Configuration
CHAT_FILE = "private_chat_data.json"
USER_FILE = "user_credentials.json"
REFRESH_INTERVAL = 2000  # milliseconds

# Initialize data files
if not os.path.exists(CHAT_FILE):
    with open(CHAT_FILE, "w") as f:
        json.dump({"sessions": {}, "users": {}}, f)

if not os.path.exists(USER_FILE):
    with open(USER_FILE, "w") as f:
        json.dump({}, f)

# Password hashing
def hash_password(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + key

def verify_password(stored_password, provided_password):
    salt = stored_password[:32]
    stored_key = stored_password[32:]
    new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return hmac.compare_digest(stored_key, new_key)

# User management
def register_user(username, password):
    with open(USER_FILE, "r") as f:
        users = json.load(f)
    if username in users:
        return False
    users[username] = {
        'password': hash_password(password).hex(),
        'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    with open(USER_FILE, "w") as f:
        json.dump(users, f)
    update_user_presence(username)
    return True

def update_user_presence(username):
    data = load_chat_data()
    if "users" not in data:
        data["users"] = {}
    data["users"][username] = {"last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    save_chat_data(data)

def authenticate_user(username, password):
    with open(USER_FILE, "r") as f:
        users = json.load(f)
    if username not in users:
        return False
    stored_password = bytes.fromhex(users[username]['password'])
    return verify_password(stored_password, password)

# Chat management
def load_chat_data():
    with open(CHAT_FILE, "r") as f:
        data = json.load(f)
    for session in data.get("sessions", {}).values():
        if "unread" not in session:
            p1, p2 = session["participants"]
            session["unread"] = {p1: False, p2: False}
    if "users" not in data:
        data["users"] = {}
    return data

def save_chat_data(data):
    with open(CHAT_FILE, "w") as f:
        json.dump(data, f)

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
    return session_id

def add_message(session_id, sender, message):
    data = load_chat_data()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    participants = data["sessions"][session_id]["participants"]
    recipient = participants[0] if participants[1] == sender else participants[1]
    data["sessions"][session_id]["unread"][recipient] = True
    data["sessions"][session_id]["messages"].append({
        "sender": sender,
        "message": message,
        "timestamp": timestamp
    })
    update_user_presence(sender)
    save_chat_data(data)

def check_unread_messages(username):
    data = load_chat_data()
    for session in data.get("sessions", {}).values():
        if username in session["participants"] and session["unread"].get(username, False):
            return session["participants"][0] if session["participants"][1] == username else session["participants"][1]
    return None

def has_new_messages(username):
    """Check if there are any new messages for the user"""
    data = load_chat_data()
    for session in data.get("sessions", {}).values():
        if username in session["participants"] and session["unread"].get(username, False):
            return True
    return False

# Authentication Page
def auth_page():
    st.title("Secure Chat")
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Login"):
                if authenticate_user(username, password):
                    st.session_state.username = username
                    st.session_state.authenticated = True
                    st.rerun()
                else:
                    st.error("Invalid credentials")
    
    with tab2:
        with st.form("register_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")
            if st.form_submit_button("Register"):
                if password != confirm:
                    st.error("Passwords don't match")
                elif len(username) < 3 or len(password) < 6:
                    st.error("Username (3+) and password (6+) too short")
                elif register_user(username, password):
                    st.success("Account created! Please login")
                else:
                    st.error("Username taken")

# Main App
def main_app():
    username = st.session_state.username
    update_user_presence(username)
    
    # Initialize last message check time
    if 'last_check' not in st.session_state:
        st.session_state.last_check = time.time()
    
    # Check for unread messages
    if "current_chat" not in st.session_state:
        unread_from = check_unread_messages(username)
        if unread_from:
            st.session_state.current_chat = unread_from
            data = load_chat_data()
            session_id = get_session(username, unread_from)
            data["sessions"][session_id]["unread"][username] = False
            save_chat_data(data)
            st.rerun()
    
    # Sidebar
    with st.sidebar:
        st.subheader(f"Hello, {username}!")
        st.write("**Online Users**")
        
        data = load_chat_data()
        active_users = [u for u, info in data.get("users", {}).items() 
                      if u != username and (datetime.now() - datetime.strptime(
                      info.get("last_seen", datetime.now().strftime("%Y-%m-%d %H:%M:%S")), 
                      "%Y-%m-%d %H:%M:%S")).seconds < 300]
        
        for user in active_users or ["No one online"]:
            if user == "No one online":
                st.caption(user)
            else:
                session_id = get_session(username, user)
                unread = data["sessions"][session_id]["unread"].get(username, False)
                if st.button(f"{user}{' 🔔' if unread else ''}"):
                    st.session_state.current_chat = user
                    data["sessions"][session_id]["unread"][username] = False
                    save_chat_data(data)
                    st.session_state.last_check = time.time()  # Reset check time on interaction
                    st.rerun()
        
        if st.button("Sign Out"):
            del st.session_state.username, st.session_state.authenticated
            if "current_chat" in st.session_state:
                del st.session_state.current_chat
            st.rerun()
    
    # Chat Area
    if "current_chat" not in st.session_state:
        st.info("← Select a user to chat")
        st.stop()
    
    other_user = st.session_state.current_chat
    session_id = get_session(username, other_user)
    
    st.subheader(f"Chat with {other_user}")
    st.markdown(timezone_js, unsafe_allow_html=True)
    
    # Display messages
    messages = load_chat_data()["sessions"][session_id]["messages"]
    for msg in messages:
        utc_time = datetime.strptime(msg["timestamp"], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
        if msg["sender"] == username:
            st.markdown(f"""
            <div class="message user-message">
                <div class="timestamp" data-utc="{utc_time}">
                    {datetime.strptime(msg["timestamp"], "%Y-%m-%d %H:%M:%S").strftime("%H:%M")}
                </div>
                {msg["message"]}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="message other-message">
                <div class="timestamp" data-utc="{utc_time}">
                    {msg["sender"]} • {datetime.strptime(msg["timestamp"], "%Y-%m-%d %H:%M:%S").strftime("%H:%M")}
                </div>
                {msg["message"]}
            </div>
            """, unsafe_allow_html=True)
    
    # Message input
    with st.form("message_form", clear_on_submit=True):
        message = st.text_area("Message", placeholder="Type your message...", 
                             height=100, label_visibility="collapsed")
        if st.form_submit_button("Send") and message.strip():
            add_message(session_id, username, message.strip())
            st.session_state.last_check = time.time()  # Reset check time on send
            st.rerun()
    
    # Check for new messages periodically
    current_time = time.time()
    if current_time - st.session_state.last_check > 2:  # Check every 2 seconds
        if has_new_messages(username):
            st.session_state.last_check = current_time
            st.rerun()
        st.session_state.last_check = current_time
    
    # Inject JavaScript to auto-refresh when new messages arrive
    st.markdown("""
    <script>
    // Check for new messages every 2 seconds
    function checkNewMessages() {
        const xhr = new XMLHttpRequest();
        xhr.open('GET', window.location.href, false);
        xhr.send();
        
        // Check if the response contains unread messages
        if (xhr.responseText.includes('🔔')) {
            window.location.reload();
        }
    }
    
    // Start checking after initial load
    setTimeout(() => {
        setInterval(checkNewMessages, 2000);
    }, 2000);
    </script>
    """, unsafe_allow_html=True)

# App flow
def main():
    if not hasattr(st.session_state, 'authenticated') or not st.session_state.authenticated:
        auth_page()
    else:
        main_app()

if __name__ == "__main__":
    main()
