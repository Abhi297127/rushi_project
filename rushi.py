from pymongo import MongoClient
import bcrypt
import re
from datetime import datetime, timedelta
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from validate_email import validate_email
import phonenumbers
import logging
from typing import Optional, Dict, Any
import streamlit as st
import cloudinary
import cloudinary.uploader
import cloudinary.api
from cloudinary.utils import cloudinary_url
import time
import streamlit.components.v1 as components

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# MongoDB setup
class DatabaseManager:
    def __init__(self, username: str, password: str):
        self.connection_string = f"mongodb+srv://{username}:{password}@cluster0.uu8yq.mongodb.net/?retryWrites=true&w=majority"
        self.client = None
        self.db = None
        self.users_collection = None
        self.activity_collection = None
        self.connect()
    def connect(self):
        try:
            self.client = MongoClient(self.connection_string)
            self.db = self.client["abhi"]
            self.users_collection = self.db["a"]
            self.activity_collection = self.db["activity_logs"]
            # Create indexes
            self.users_collection.create_index("email", unique=True)
            self.users_collection.create_index("mobile", unique=True)
            logger.info("Successfully connected to MongoDB")
        except Exception as e:
            logger.error(f"Database connection error: {str(e)}")
            st.error("Database connection failed. Please try again later.")
class Utils:
    @staticmethod
    def is_email_valid(email: str) -> bool:
        try:
            return validate_email(email)
        except:
            return False
    @staticmethod
    def is_mobile_valid(mobile: str) -> bool:
        try:
            parsed_number = phonenumbers.parse(mobile, "IN")
            return phonenumbers.is_valid_number(parsed_number)
        except:
            return False
    @staticmethod
    def hash_password(password: str) -> bytes:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    @staticmethod
    def verify_password(password: str, hashed: bytes) -> bool:
        return bcrypt.checkpw(password.encode('utf-8'), hashed)
    @staticmethod
    def log_activity(db: DatabaseManager, user_id: str, action: str):
        db.activity_collection.insert_one({
            "user_id": user_id,
            "action": action,
            "timestamp": datetime.utcnow()
        })
class AuthenticationSystem:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.utils = Utils()
    def handle_registration(self):
        st.title("Register")
        
        with st.form("register_form", clear_on_submit=True):
            # Form inputs (same as original code)
            col1, col2 = st.columns(2)
            with col1:
                first_name = st.text_input("First Name")
            with col2:
                last_name = st.text_input("Last Name")
            
            col3, col4 = st.columns(2)
            with col3:
                email = st.text_input("Email")
            with col4:
                mobile = st.text_input("Mobile Number")
            
            col5, col6 = st.columns(2)
            with col5:
                password = st.text_input("Password", type="password")
            with col6:
                confirm_password = st.text_input("Confirm Password", type="password")
            # Password requirements
            if password:
                if len(password) < 8:
                    st.warning("Password must be at least 8 characters long")
                if not any(c.isupper() for c in password):
                    st.warning("Password must contain at least one uppercase letter")
                if not any(c.isdigit() for c in password):
                    st.warning("Password must contain at least one number")
            terms = st.checkbox("I agree to the Terms and Conditions")
            submitted = st.form_submit_button("Register")
            if submitted:
                if not all([first_name, last_name, email, mobile, password, confirm_password]):
                    st.error("All fields are required.")
                elif not self.utils.is_email_valid(email):
                    st.error("Invalid email format.")
                elif not self.utils.is_mobile_valid(mobile):
                    st.error("Invalid mobile number format.")
                elif password != confirm_password:
                    st.error("Passwords do not match.")
                elif not terms:
                    st.error("Please accept the Terms and Conditions.")
                else:
                    try:
                        hashed_password = self.utils.hash_password(password)
                        self.db.users_collection.insert_one({
                            "first_name": first_name,
                            "last_name": last_name,
                            "email": email,
                            "mobile": mobile,
                            "password": hashed_password,
                            "status": "no",
                            "created_at": datetime.utcnow(),
                            "last_login": None
                        })
                        st.success("Registration successful! Please wait for admin approval.")
                        st.session_state.page = "login"
                    except Exception as e:
                        if "duplicate key error" in str(e):
                            st.error("Email or mobile number already registered.")
                        else:
                            logger.error(f"Registration error: {str(e)}")
                            st.error("Registration failed. Please try again.")
    def handle_login(self):
        st.title("Login")
        with st.form("login_form"):
            identifier = st.text_input("Email or Mobile Number")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            if submitted:
                user = self.db.users_collection.find_one({
                    "$or": [
                        {"email": identifier},
                        {"mobile": identifier}
                    ]
                })
                if not user:
                    st.error("Account not found.")
                elif not self.utils.verify_password(password, user['password']):
                    st.error("Incorrect password.")
                elif user['status'] == "no":
                    st.error("Your account is not active. Contact admin.")
                else:
                    self.db.users_collection.update_one(
                        {"_id": user['_id']},
                        {"$set": {"last_login": datetime.utcnow()}}
                    )
                    self.utils.log_activity(self.db, str(user['_id']), "login")
                    st.success(f"Welcome {user['first_name']} {user['last_name']}!")
                    st.session_state['logged_in'] = True
                    st.session_state['user'] = user
                    st.rerun()
class AdminPanel:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.utils = Utils()
    def render(self):
        st.title("Admin Dashboard")
        
        if not self._verify_admin():
            return
        # Improved navigation with tabs
        tabs = st.tabs(["📊 Analytics", "👥 User Management", "📝 Activity Logs"])
        
        with tabs[0]:
            self._analytics()
        with tabs[1]:
            self._user_management()
        with tabs[2]:
            self._activity_logs()
    def _verify_admin(self) -> bool:
        if "logged_in" in st.session_state and st.session_state.get('user', {}).get('status') == "admin":
            return True
        st.error("Access denied. Only admin can access this page.")
        return False
    def _user_management(self):
        st.subheader("User Management")
        
        users = list(self.db.users_collection.find())
        user_df = pd.DataFrame(users)
        
        # Enhanced filter options
        col1, col2 = st.columns([2, 3])
        with col1:
            status_filter = st.multiselect("Filter by Status", ["yes", "no", "admin"])
        with col2:
            search = st.text_input("🔍 Search by name or email")
        if status_filter:
            user_df = user_df[user_df['status'].isin(status_filter)]
        if search:
            mask = (
                user_df['first_name'].str.contains(search, case=False, na=False) |
                user_df['last_name'].str.contains(search, case=False, na=False) |
                user_df['email'].str.contains(search, case=False, na=False)
            )
            user_df = user_df[mask]
        # Display users in a modern card layout
        for _, user in user_df.iterrows():
            with st.container():
                st.markdown("""
                    <style>
                        .user-card {
                            border: 1px solid #e1e4e8;
                            border-radius: 6px;
                            padding: 16px;
                            margin: 8px 0;
                        }
                    </style>
                """, unsafe_allow_html=True)
                
                with st.expander(f"👤 {user['first_name']} {user['last_name']} ({user['email']})"):
                    col1, col2 = st.columns([3, 1])
                    
                    with col1:
                        st.write(f"📱 Mobile: {user['mobile']}")
                        st.write(f"🔵 Status: {user['status']}")
                        st.write(f"📅 Created: {user['created_at'].strftime('%Y-%m-%d %H:%M')}")
                        st.write(f"🕒 Last Login: {user.get('last_login', 'Never')}")
                    
                    with col2:
                        if user['status'] == "no":
                            if st.button("✅ Activate", key=f"activate_{user['_id']}"):
                                self.db.users_collection.update_one(
                                    {"_id": user['_id']},
                                    {"$set": {"status": "yes"}}
                                )
                                self.utils.log_activity(self.db, str(user['_id']), "user_activated")
                                st.success("User activated!")
                                st.rerun()
                        
                        if user['status'] != "admin":
                            if st.button("👑 Make Admin", key=f"admin_{user['_id']}"):
                                self.db.users_collection.update_one(
                                    {"_id": user['_id']},
                                    {"$set": {"status": "admin"}}
                                )
                                self.utils.log_activity(self.db, str(user['_id']), "made_admin")
                                st.success("User promoted!")
                                st.rerun()
                        if st.button("🗑️ Delete", key=f"delete_{user['_id']}"):
                            self.db.users_collection.delete_one({"_id": user['_id']})
                            self.utils.log_activity(self.db, str(user['_id']), "user_deleted")
                            st.success("User deleted!")
                            st.rerun()
    def _analytics(self):
        st.subheader("Analytics Dashboard")
        
        # Fetch user data
        users = list(self.db.users_collection.find())
        df = pd.DataFrame(users)
        
        # Key Metrics
        col1, col2, col3, col4 = st.columns(4)
        total_users = len(users)
        active_users = len([u for u in users if u['status'] == "yes"])
        pending_users = len([u for u in users if u['status'] == "no"])
        admin_users = len([u for u in users if u['status'] == "admin"])
        
        col1.metric("👥 Total Users", total_users)
        col2.metric("✅ Active Users", active_users)
        col3.metric("⏳ Pending", pending_users)
        col4.metric("👑 Admins", admin_users)
        
        # Time-based Analysis
        st.subheader("User Growth Analysis")
        
        df['created_at'] = pd.to_datetime(df['created_at'])
        df['date'] = df['created_at'].dt.date
        
        # Registration Trend
        daily_registrations = df.groupby('date').size().reset_index(name='count')
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=daily_registrations['date'],
            y=daily_registrations['count'],
            mode='lines+markers',
            name='Registrations',
            line=dict(color='#1f77b4'),
            fill='tozeroy'
        ))
        fig.update_layout(
            title='Daily Registration Trend',
            xaxis_title='Date',
            yaxis_title='Number of Registrations',
            hovermode='x unified'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # User Status Distribution
        status_dist = df['status'].value_counts()
        fig_pie = px.pie(
            values=status_dist.values,
            names=status_dist.index,
            title='User Status Distribution',
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    def _activity_logs(self):
        st.subheader("Activity Logs")
        
        # Fetch and prepare activity logs
        logs = list(self.db.activity_collection.find().sort("timestamp", -1).limit(100))
        if logs:
            log_df = pd.DataFrame(logs)
            log_df['timestamp'] = pd.to_datetime(log_df['timestamp'])
            
            # Activity Visualization
            # Using scatter plot instead of timeline
            fig = px.scatter(
                log_df,
                x="timestamp",
                y="action",
                title="Recent Activity Visualization",
                color="action",
                size=[10] * len(log_df),  # Constant size for all points
                template="plotly_white"
            )
            
            # Customize the layout
            fig.update_traces(marker=dict(symbol='circle'))
            fig.update_layout(
                showlegend=True,
                xaxis_title="Time",
                yaxis_title="Activity Type",
                height=400,
                yaxis={'categoryorder': 'category ascending'}
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Activity Summary
            st.subheader("Activity Summary")
            activity_counts = log_df['action'].value_counts()
            
            # Create a bar chart for activity distribution
            fig_bar = px.bar(
                x=activity_counts.index,
                y=activity_counts.values,
                title="Activity Distribution",
                labels={'x': 'Activity Type', 'y': 'Count'},
                color=activity_counts.values,
                color_continuous_scale='Viridis'
            )
            
            st.plotly_chart(fig_bar, use_container_width=True)
            
            # Detailed Log Table
            st.subheader("Detailed Activity Log")
            styled_df = log_df.copy()
            styled_df['timestamp'] = styled_df['timestamp'].dt.strftime("%Y-%m-%d %H:%M:%S")
            
            # Enhanced table display
            st.dataframe(
                styled_df[['timestamp', 'user_id', 'action']].sort_values(by='timestamp', ascending=False),
                column_config={
                    "timestamp": st.column_config.Column(
                        "Time",
                        width="medium",
                    ),
                    "user_id": st.column_config.Column(
                        "User ID",
                        width="medium",
                    ),
                    "action": st.column_config.Column(
                        "Action",
                        width="medium",
                    )
                },
                hide_index=True,
                use_container_width=True
            )
        else:
            st.info("No activity logs found")

logger = logging.getLogger(__name__)
class UserDashboard:
    def __init__(self, db, user):
        self.db = db
        self.user = user
        
        # Initialize Cloudinary configuration with error handling
        try:
            cloudinary.config(
                cloud_name="dqyvhqdgw",  # Replace with your Cloudinary cloud name
                api_key="148221967529191",  # Replace with your Cloudinary API key
                api_secret="m_F3x5WXUWVrRnGhzDdo7wZIRy0"  # Replace with your Cloudinary API secret
            )
            # Verify credentials by making a test API call
            self._verify_cloudinary_credentials()
        except Exception as e:
            logger.error(f"Cloudinary configuration error: {str(e)}")
            st.error("Error initializing media service. Please check your credentials.")

    def _verify_cloudinary_credentials(self):
        """Verify Cloudinary credentials by making a test API call"""
        try:
            # Try to get account info as a test
            cloudinary.api.ping()
            logger.info("Cloudinary credentials verified successfully")
        except Exception as e:
            logger.error(f"Cloudinary credential verification failed: {str(e)}")
            raise Exception("Failed to verify Cloudinary credentials")

    def render(self):
        st.title(f"Welcome, {self.user['first_name']}!")
        
        tabs = st.tabs(["📊 Dashboard", "👤 Profile", "⚙️ Settings", "📸 Photo Gallery"])
        
        with tabs[0]:
            self._show_dashboard()
        with tabs[1]:
            self._show_profile()
        with tabs[2]:
            self._show_settings()
        with tabs[3]:
            self._show_photos()

    def _show_photos(self):
        st.subheader("Photo Gallery")
        
        try:
            # First verify Cloudinary connection
            self._verify_cloudinary_credentials()
            
            # Fetch images with better error handling
            try:
                result = cloudinary.api.resources(
                    type='upload',  # Fetch uploaded resources
                    prefix='abhi/',  # Replace with your folder path in Cloudinary
                    max_results=100,  # Limit the number of results
                    resource_type='image'  # Fetch only images
                )
            except cloudinary.api.Error as api_error:
                logger.error(f"Cloudinary API error: {str(api_error)}")
                st.error("Unable to fetch media files. Please check your Cloudinary configuration and try again.")
                return
            except Exception as api_error:
                logger.error(f"Unexpected error fetching resources: {str(api_error)}")
                st.error("An unexpected error occurred while fetching media files. Please try again later.")
                return

            if not result.get('resources'):
                st.info("No media files found in the gallery.")
                return
            
            # Display images in a grid view
            cols = st.columns(3)  # Create 3 columns for the grid
            
            for idx, resource in enumerate(result['resources']):
                with cols[idx % 3]:  # Distribute images across columns
                    try:
                        public_id = resource.get('public_id', '')
                        format = resource.get('format', '')
                        
                        # Generate URL for the image in its original size
                        original_image_url, options = cloudinary_url(
                            public_id,
                            format=format,
                            # No width, height, or crop parameters
                        )
                        
                        # Display the image in its original size
                        st.image(original_image_url, use_container_width=False)
                        
                        # Add file information and controls
                        display_name = public_id.split('/')[-1]
                        col_a = st.columns([2, 1])
                        with col_a:
                            st.caption(display_name)
                        
                    
                    except Exception as img_error:
                        logger.error(f"Error displaying media: {str(img_error)}")
                        continue

        except Exception as e:
            logger.error(f"Gallery error: {str(e)}")
            st.error("Error loading media gallery. Please try again later.")    
    
    def _show_dashboard(self):
            st.subheader("Your Activity")
            
            # Fetch user's activity logs
            logs = list(self.db.activity_collection.find({"user_id": str(self.user['_id'])}
            ).sort("timestamp", -1))
            
            if logs:
                log_df = pd.DataFrame(logs)
                log_df['timestamp'] = pd.to_datetime(log_df['timestamp'])
                
                # Activity Summary
                col1, col2 = st.columns(2)
                
                with col1:
                    # Recent Activity Chart
                    activity_counts = log_df['action'].value_counts()
                    fig = px.pie(
                        values=activity_counts.values,
                        names=activity_counts.index,
                        title='Your Activity Distribution',
                        color_discrete_sequence=px.colors.qualitative.Set3
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    # Activity Timeline
                    fig = px.scatter(
                        log_df,
                        x='timestamp',
                        y='action',
                        title='Your Activity Timeline',
                        color='action'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                # Recent Activity List
                st.subheader("Recent Activities")
                for _, log in log_df.head(5).iterrows():
                    st.write(f"🔹 {log['action']} - {log['timestamp'].strftime('%Y-%m-%d %H:%M')}")
            else:
                st.info("No activity recorded yet")
    def _show_profile(self):
            st.subheader("My Profile")
            
            # Profile Information
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("""
                    <div style='padding: 15px; border: 1px solid #f0f2f6; border-radius: 5px;'>
                        <h4>Personal Information</h4>
                    </div>
                """, unsafe_allow_html=True)
                st.write(f"**Full Name:** {self.user['first_name']} {self.user['last_name']}")
                st.write(f"**Email:** {self.user['email']}")
                st.write(f"**Mobile:** {self.user['mobile']}")
                
            with col2:
                st.markdown("""
                    <div style='padding: 15px; border: 1px solid #f0f2f6; border-radius: 5px;'>
                        <h4>Account Information</h4>
                    </div>
                """, unsafe_allow_html=True)
                st.write(f"**Account Status:** {self.user['status']}")
                st.write(f"**Last Login:** {self.user.get('last_login', 'Never')}")
                st.write(f"**Account Created:** {self.user['created_at'].strftime('%Y-%m-%d %H:%M')}")
    def _show_settings(self):
            st.subheader("Settings")
            
            with st.form("settings_form"):
                # Personal Information Section
                st.markdown("### Personal Information")
                col1, col2 = st.columns(2)
                
                with col1:
                    first_name = st.text_input("First Name", value=self.user['first_name'])
                    email = st.text_input("Email", value=self.user['email'], disabled=True)
                    
                with col2:
                    last_name = st.text_input("Last Name", value=self.user['last_name'])
                    mobile = st.text_input("Mobile", value=self.user['mobile'], disabled=True)
                
                # Password Change Section
                st.markdown("### Change Password")
                col3, col4 = st.columns(2)
                
                with col3:
                    current_password = st.text_input("Current Password", type="password")
                    new_password = st.text_input("New Password (optional)", type="password")
                    
                with col4:
                    password_requirements = """
                    Password Requirements:
                    - At least 8 characters
                    - One uppercase letter
                    - One number
                    """
                    st.markdown(password_requirements)
                
                submitted = st.form_submit_button("Save Changes")
                
                if submitted:
                    if current_password:
                        if not self.utils.verify_password(current_password, self.user['password']):
                            st.error("Current password is incorrect.")
                            return
                        
                        update_data = {
                            "first_name": first_name,
                            "last_name": last_name,
                        }
                        
                        if new_password:
                            if len(new_password) < 8:
                                st.error("New password must be at least 8 characters long")
                                return
                            if not any(c.isupper() for c in new_password):
                                st.error("New password must contain at least one uppercase letter")
                                return
                            if not any(c.isdigit() for c in new_password):
                                st.error("New password must contain at least one number")
                                return
                            
                            update_data["password"] = self.utils.hash_password(new_password)
                        
                        try:
                            self.db.users_collection.update_one(
                                {"_id": self.user['_id']},
                                {"$set": update_data}
                            )
                            self.utils.log_activity(self.db, str(self.user['_id']), "profile_updated")
                            st.success("Profile updated successfully!")
                            # Update session state
                            updated_user = self.db.users_collection.find_one({"_id": self.user['_id']})
                            st.session_state['user'] = updated_user
                            st.rerun()
                        except Exception as e:
                            logger.error(f"Profile update error: {str(e)}")
                            st.error("Failed to update profile. Please try again.")
                    else:
                        st.error("Please enter your current password to save changes.")


def main():
    st.set_page_config(
        page_title="User Authentication System",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS
    st.markdown("""
        <style>
        .stButton>button {
            width: 100%;
        }
        .stTextInput>div>div>input {
            color: #4F8BF9;
        }
        </style>
        """, unsafe_allow_html=True)
    
    # Initialize session state
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'page' not in st.session_state:
        st.session_state.page = "login"
    
    # Initialize database connection
    db = DatabaseManager(username="abhishelke297127", password="Abhi%402971")
    auth_system = AuthenticationSystem(db)
    
    # Sidebar navigation with improved styling
    with st.sidebar:
        st.title("🔐 Navigation")
        if st.session_state.logged_in:
            user = st.session_state.user
            st.write(f"Welcome, {user['first_name']}!")
            if st.button("📤 Logout", key="logout"):
                st.session_state.logged_in = False
                st.session_state.user = None
                st.session_state.page = "login"
                st.rerun()
            if st.sidebar.button("🔄 Refresh", key="refresh"):
                st.rerun()
        else:
            page = st.radio("Choose Option", ["🔑 Login", "📝 Register"])
            st.session_state.page = page.split()[-1].lower()
    
    # Main content
    if st.session_state.logged_in:
        user = st.session_state.user
        if user['status'] == "admin":
            admin_panel = AdminPanel(db)
            admin_panel.render()
        else:
            user_dashboard = UserDashboard(db, user)
            user_dashboard.render()
    else:
        if st.session_state.page == "register":
            auth_system.handle_registration()
        else:
            auth_system.handle_login()
if __name__ == "__main__":
    main()