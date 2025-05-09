import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import os
from datetime import datetime, date
from tkcalendar import DateEntry  # You'll need to install this: pip install tkcalendar

# =============== DATABASE FUNCTIONS ===============

def initialize_database(db_path):
    """Initialize the SQLite database with required tables"""
    
    # Check if database file exists
    db_exists = os.path.exists(db_path)
    
    # Connect to database (creates it if it doesn't exist)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables if they don't exist
    cursor.executescript('''
    -- Users Table (Admin, Faculty, Students)
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'faculty', 'student')),
        email TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Subjects Table
    CREATE TABLE IF NOT EXISTS Subjects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_code TEXT UNIQUE NOT NULL,
        subject_name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Classes Table
    CREATE TABLE IF NOT EXISTS Classes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        class_name TEXT NOT NULL,
        semester INTEGER,
        section TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(class_name, semester, section)
    );

    -- Student-Class Mapping
    CREATE TABLE IF NOT EXISTS StudentClass (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER,
        class_id INTEGER,
        FOREIGN KEY (student_id) REFERENCES Users(id),
        FOREIGN KEY (class_id) REFERENCES Classes(id),
        UNIQUE(student_id, class_id)
    );

    -- Faculty-Subject-Class Mapping
    CREATE TABLE IF NOT EXISTS FacultySubjectClass (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        faculty_id INTEGER,
        subject_id INTEGER,
        class_id INTEGER,
        FOREIGN KEY (faculty_id) REFERENCES Users(id),
        FOREIGN KEY (subject_id) REFERENCES Subjects(id),
        FOREIGN KEY (class_id) REFERENCES Classes(id),
        UNIQUE(faculty_id, subject_id, class_id)
    );

    -- Attendance Records
    CREATE TABLE IF NOT EXISTS Attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER,
        subject_id INTEGER,
        class_id INTEGER,
        date DATE NOT NULL,
        status TEXT CHECK (status IN ('present', 'absent', 'late')),
        marked_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (student_id) REFERENCES Users(id),
        FOREIGN KEY (subject_id) REFERENCES Subjects(id),
        FOREIGN KEY (class_id) REFERENCES Classes(id),
        FOREIGN KEY (marked_by) REFERENCES Users(id),
        UNIQUE(student_id, subject_id, date)
    );
    ''')
    
    # Insert default admin user if not exists
    cursor.execute("SELECT COUNT(*) FROM Users WHERE role = 'admin'")
    admin_count = cursor.fetchone()[0]
    
    if admin_count == 0:
        cursor.execute(
            "INSERT INTO Users (user_id, password, name, role, email) VALUES (?, ?, ?, ?, ?)",
            ('admin', 'admin123', 'System Administrator', 'admin', 'admin@college.edu')
        )
        print("Default admin user created")
    
    # Commit changes and close connection
    conn.commit()
    conn.close()


def get_db_connection():
    """Create and return a database connection"""
    conn = sqlite3.connect('attendance.db')
    conn.row_factory = sqlite3.Row  # This enables column access by name
    return conn


def authenticate_user(user_id, password):
    """Authenticate user by user_id and password"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM Users WHERE user_id = ? AND password = ?", (user_id, password))
    user = cursor.fetchone()
    
    conn.close()
    
    if user:
        return dict(user)  # Convert to regular dictionary
    return None


def get_all_users(role=None):
    """Get all users or filter by role"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if role and role != 'all':
        cursor.execute("SELECT * FROM Users WHERE role = ?", (role,))
    else:
        cursor.execute("SELECT * FROM Users")
        
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return users


def add_user(user_id, password, name, role, email):
    """Add a new user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO Users (user_id, password, name, role, email) VALUES (?, ?, ?, ?, ?)",
            (user_id, password, name, role, email)
        )
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        return last_id
    except sqlite3.IntegrityError:
        conn.close()
        return -1  # User ID already exists


def get_all_subjects():
    """Get all subjects"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM Subjects")
    subjects = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return subjects


def add_subject(subject_code, subject_name):
    """Add a new subject"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO Subjects (subject_code, subject_name) VALUES (?, ?)",
            (subject_code, subject_name)
        )
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        return last_id
    except sqlite3.IntegrityError:
        conn.close()
        return -1  # Subject code already exists


def get_all_classes():
    """Get all classes"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM Classes")
    classes = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return classes


def add_class(class_name, semester, section):
    """Add a new class"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO Classes (class_name, semester, section) VALUES (?, ?, ?)",
            (class_name, semester, section)
        )
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        return last_id
    except sqlite3.IntegrityError:
        conn.close()
        return -1  # Class combination already exists


def assign_faculty(faculty_id, subject_id, class_id):
    """Assign faculty to subject and class"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO FacultySubjectClass (faculty_id, subject_id, class_id) VALUES (?, ?, ?)",
            (faculty_id, subject_id, class_id)
        )
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        return last_id
    except sqlite3.IntegrityError:
        conn.close()
        return -1  # Assignment already exists


def assign_student_to_class(student_id, class_id):
    """Assign student to class"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO StudentClass (student_id, class_id) VALUES (?, ?)",
            (student_id, class_id)
        )
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        return last_id
    except sqlite3.IntegrityError:
        conn.close()
        return -1  # Assignment already exists


def get_faculty_assignments(faculty_id):
    """Get faculty's assigned classes and subjects"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT fsc.id, s.subject_code, s.subject_name, c.class_name, c.semester, c.section, s.id AS subject_id, c.id AS class_id
        FROM FacultySubjectClass fsc
        JOIN Subjects s ON fsc.subject_id = s.id
        JOIN Classes c ON fsc.class_id = c.id
        WHERE fsc.faculty_id = ?
    """, (faculty_id,))
    
    assignments = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return assignments


def get_class_students(class_id):
    """Get students in a class"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT u.id, u.user_id, u.name, u.email
        FROM StudentClass sc
        JOIN Users u ON sc.student_id = u.id
        WHERE sc.class_id = ? AND u.role = 'student'
    """, (class_id,))
    
    students = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return students


def mark_attendance(student_id, subject_id, class_id, date, status, marked_by):
    """Mark or update student attendance"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Try to update first
        cursor.execute("""
            UPDATE Attendance 
            SET status = ?, marked_by = ? 
            WHERE student_id = ? AND subject_id = ? AND date = ?
        """, (status, marked_by, student_id, subject_id, date))
        
        if cursor.rowcount == 0:
            # If no rows were updated, insert new record
            cursor.execute("""
                INSERT INTO Attendance (student_id, subject_id, class_id, date, status, marked_by)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (student_id, subject_id, class_id, date, status, marked_by))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error marking attendance: {e}")
        conn.close()
        return False


def get_student_attendance(student_id):
    """Get attendance records for a student"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT a.id, a.date, a.status, s.subject_code, s.subject_name, c.class_name
        FROM Attendance a
        JOIN Subjects s ON a.subject_id = s.id
        JOIN Classes c ON a.class_id = c.id
        WHERE a.student_id = ?
        ORDER BY a.date DESC
    """, (student_id,))
    
    attendance = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return attendance


def calculate_attendance_stats(student_id):
    """Calculate attendance statistics for a student"""
    attendance_records = get_student_attendance(student_id)
    
    # Initialize statistics
    subject_stats = {}
    total_classes = 0
    total_present = 0
    
    # Process attendance records
    for record in attendance_records:
        subject_code = record['subject_code']
        
        if subject_code not in subject_stats:
            subject_stats[subject_code] = {
                'name': record['subject_name'],
                'total': 0,
                'present': 0,
                'absent': 0,
                'late': 0,
                'percentage': 0
            }
        
        subject_stats[subject_code]['total'] += 1
        total_classes += 1
        
        if record['status'] == 'present':
            subject_stats[subject_code]['present'] += 1
            total_present += 1
        elif record['status'] == 'absent':
            subject_stats[subject_code]['absent'] += 1
        elif record['status'] == 'late':
            subject_stats[subject_code]['late'] += 1
            # Count late as present for percentage calculation
            subject_stats[subject_code]['present'] += 1
            total_present += 1
    
    # Calculate percentages
    for subject in subject_stats.values():
        if subject['total'] > 0:
            subject['percentage'] = (subject['present'] / subject['total']) * 100
    
    overall_percentage = (total_present / total_classes) * 100 if total_classes > 0 else 0
    
    return {
        'subjects': subject_stats,
        'overall': {
            'total': total_classes,
            'present': total_present,
            'percentage': overall_percentage
        }
    }

# =============== LOGIN SCREEN ===============

class LoginScreen(tk.Frame):
    def __init__(self, parent, on_login_callback):
        super().__init__(parent)
        self.parent = parent
        self.on_login_callback = on_login_callback
        
        self.configure_styles()
        self.create_widgets()
        self.pack(fill="both", expand=True)
    
    def configure_styles(self):
        style = ttk.Style()
        
        # Configure label styles
        style.configure('Title.TLabel', font=('Arial', 18, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        
        # Configure button styles
        style.configure('Primary.TButton', font=('Arial', 12))
    
    def create_widgets(self):
        # Main container with padding
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill="both", expand=True)
        
        # Center login form
        center_frame = ttk.Frame(main_frame)
        center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # Title
        ttk.Label(
            center_frame, 
            text="College Attendance Management System", 
            style='Title.TLabel'
        ).pack(pady=(0, 20))
        
        # Login form
        login_frame = ttk.LabelFrame(center_frame, text="Login", padding=20)
        login_frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        # Error message (hidden initially)
        self.error_var = tk.StringVar()
        self.error_label = ttk.Label(
            login_frame, 
            textvariable=self.error_var, 
            foreground="red",
            wraplength=300
        )
        self.error_label.pack(pady=(0, 10), fill="x")
        self.error_label.pack_forget()  # Hide initially
        
        # User ID
        ttk.Label(login_frame, text="User ID:").pack(anchor=tk.W, pady=(0, 5))
        self.user_id_var = tk.StringVar()
        user_id_entry = ttk.Entry(login_frame, textvariable=self.user_id_var, width=30)
        user_id_entry.pack(fill="x", pady=(0, 10))
        
        # Password
        ttk.Label(login_frame, text="Password:").pack(anchor=tk.W, pady=(0, 5))
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(login_frame, textvariable=self.password_var, show="●", width=30)
        password_entry.pack(fill="x", pady=(0, 20))
        
        # Login button
        login_button = ttk.Button(
            login_frame, 
            text="Login", 
            style='Primary.TButton', 
            command=self.handle_login
        )
        login_button.pack(fill="x")
        
        # Set focus to user ID field
        user_id_entry.focus_set()
        
        # Bind Enter key to login
        self.parent.bind("<Return>", lambda event: self.handle_login())
    
    def handle_login(self):
        user_id = self.user_id_var.get().strip()
        password = self.password_var.get().strip()
        
        if not user_id or not password:
            self.show_error("User ID and Password are required")
            return
        
        # Authenticate user
        user_data = authenticate_user(user_id, password)
        
        if user_data:
            self.parent.unbind("<Return>")  # Unbind Enter key
            self.on_login_callback(user_data)
        else:
            self.show_error("Invalid credentials. Please try again.")
    
    def show_error(self, message):
        self.error_var.set(message)
        self.error_label.pack(pady=(0, 10), fill="x")  # Show error label

# =============== ADMIN DASHBOARD ===============

class AdminDashboard(tk.Frame):
    def __init__(self, parent, user_data, logout_callback):
        super().__init__(parent)
        self.parent = parent
        self.user_data = user_data
        self.logout_callback = logout_callback
        
        self.configure_styles()
        self.create_widgets()
        self.pack(fill="both", expand=True)
        
        # Default to user management tab
        self.show_tab("users")
    
    def configure_styles(self):
        style = ttk.Style()
        
        # Configure label styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Subheader.TLabel', font=('Arial', 12, 'bold'))
        
        # Configure button styles
        style.configure('NavButton.TButton', font=('Arial', 11))
        style.configure('Primary.TButton', font=('Arial', 11))
        style.configure('Secondary.TButton', font=('Arial', 11))
        
        # Configure treeview
        style.configure('Treeview.Heading', font=('Arial', 11, 'bold'))
    
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True)
        
        # Top navigation bar
        nav_frame = ttk.Frame(main_frame, padding=10, relief='ridge', borderwidth=1)
        nav_frame.pack(fill="x")
        
        # Title and user info
        title_frame = ttk.Frame(nav_frame)
        title_frame.pack(side=tk.LEFT)
        
        ttk.Label(title_frame, text="College Attendance Management System", style='Title.TLabel').pack(anchor=tk.W)
        ttk.Label(title_frame, text=f"Logged in as: {self.user_data['name']} (Admin)").pack(anchor=tk.W)
        
        # Logout button
        logout_btn = ttk.Button(nav_frame, text="Logout", command=self.logout_callback, style='NavButton.TButton')
        logout_btn.pack(side=tk.RIGHT)
        
        # Content area with sidebar and main content
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill="both", expand=True, pady=10)
        
        # Sidebar
        sidebar_frame = ttk.Frame(content_frame, width=200, relief='ridge', borderwidth=1)
        sidebar_frame.pack(side=tk.LEFT, fill="y", padx=(0, 10))
        sidebar_frame.pack_propagate(False)  # Prevent shrinking
        
        # Sidebar title
        ttk.Label(sidebar_frame, text="Admin Panel", style='Subheader.TLabel').pack(anchor=tk.W, padx=10, pady=10)
        
        # Sidebar navigation buttons
        self.nav_buttons = {}
        
        nav_options = [
            ("User Management", "users"),
            ("Subject Management", "subjects"),
            ("Class Management", "classes"),
            ("Assignments", "assignments"),
            ("Attendance Reports", "reports")
        ]
        
        for text, tab_id in nav_options:
            btn = ttk.Button(
                sidebar_frame,
                text=text,
                command=lambda t=tab_id: self.show_tab(t),
                style='NavButton.TButton',
                width=25
            )
            btn.pack(fill="x", padx=5, pady=2)
            self.nav_buttons[tab_id] = btn
        
        # Main content area
        self.content_area = ttk.Frame(content_frame)
        self.content_area.pack(side=tk.RIGHT, fill="both", expand=True)
        
        # Create all tab frames
        self.create_tab_frames()
    
    def create_tab_frames(self):
        # Create frames for each tab
        self.tab_frames = {
            "users": self.create_user_management_tab(),
            "subjects": self.create_subject_management_tab(),
            "classes": self.create_class_management_tab(),
            "assignments": self.create_assignment_management_tab(),
            "reports": self.create_reports_tab()
        }
    
    def show_tab(self, tab_id):
        # Hide all frames
        for frame in self.tab_frames.values():
            frame.pack_forget()
        
        # Reset all button styles
        for btn in self.nav_buttons.values():
            btn.configure(style='NavButton.TButton')
        
        # Show selected frame
        self.tab_frames[tab_id].pack(fill="both", expand=True)
        
        # Highlight selected button
        self.nav_buttons[tab_id].configure(style='Primary.TButton')
        
        # Refresh tab data
        self.refresh_tab_data(tab_id)
    
    def refresh_tab_data(self, tab_id):
        if tab_id == "users":
            self.refresh_users()
        elif tab_id == "subjects":
            self.refresh_subjects()
        elif tab_id == "classes":
            self.refresh_classes()
        elif tab_id == "assignments":
            self.refresh_assignments()
        elif tab_id == "reports":
            self.refresh_reports()
    
    def create_user_management_tab(self):
        frame = ttk.Frame(self.content_area, padding=10)
        
        # Header section
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(header_frame, text="User Management", style='Header.TLabel').pack(side=tk.LEFT)
        
        # Actions frame
        actions_frame = ttk.Frame(header_frame)
        actions_frame.pack(side=tk.RIGHT)
        
        # Role filter dropdown
        ttk.Label(actions_frame, text="Filter by role:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.role_filter_var = tk.StringVar(value="all")
        role_filter = ttk.Combobox(
            actions_frame, 
            textvariable=self.role_filter_var,
            values=["all", "faculty", "student"],
            width=10,
            state="readonly"
        )
        role_filter.pack(side=tk.LEFT, padx=(0, 10))
        role_filter.bind("<<ComboboxSelected>>", lambda e: self.refresh_users())
        
        # Add user button
        add_user_btn = ttk.Button(
            actions_frame,
            text="Add User",
            command=self.show_add_user_form,
            style='Primary.TButton'
        )
        add_user_btn.pack(side=tk.RIGHT)
        
        # Add user form (initially hidden)
        self.add_user_frame = ttk.LabelFrame(frame, text="Add New User", padding=10)
        
        # Form fields
        form_grid = ttk.Frame(self.add_user_frame)
        form_grid.pack(fill="x", expand=True)
        
        # User ID
        ttk.Label(form_grid, text="User ID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.new_user_id = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.new_user_id, width=20).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Password
        ttk.Label(form_grid, text="Password:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.new_password = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.new_password, width=20).grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Name
        ttk.Label(form_grid, text="Full Name:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.new_name = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.new_name, width=20).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Role
        ttk.Label(form_grid, text="Role:").grid(row=1, column=2, sticky=tk.W, pady=5)
        self.new_role = tk.StringVar(value="faculty")
        role_combo = ttk.Combobox(
            form_grid, 
            textvariable=self.new_role,
            values=["faculty", "student"],
            width=10,
            state="readonly"
        )
        role_combo.grid(row=1, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Email
        ttk.Label(form_grid, text="Email:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.new_email = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.new_email, width=20).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Form action buttons
        btn_frame = ttk.Frame(form_grid)
        btn_frame.grid(row=3, column=0, columnspan=4, sticky=tk.E, pady=10)
        
        ttk.Button(
            btn_frame, 
            text="Save", 
            command=self.add_user, 
            style='Primary.TButton'
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            btn_frame, 
            text="Cancel", 
            command=lambda: self.add_user_frame.pack_forget(), 
            style='Secondary.TButton'
        ).pack(side=tk.LEFT)
        
        # Users table
        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True, pady=(10, 0))
        
        # Create treeview
        columns = ("id", "user_id", "name", "role", "email", "created_at")
        self.users_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        # Define headings
        self.users_tree.heading("id", text="ID")
        self.users_tree.heading("user_id", text="User ID")
        self.users_tree.heading("name", text="Name")
        self.users_tree.heading("role", text="Role")
        self.users_tree.heading("email", text="Email")
        self.users_tree.heading("created_at", text="Created At")
        
        # Define columns
        self.users_tree.column("id", width=50, anchor=tk.CENTER)
        self.users_tree.column("user_id", width=100)
        self.users_tree.column("name", width=200)
        self.users_tree.column("role", width=100)
        self.users_tree.column("email", width=200)
        self.users_tree.column("created_at", width=150)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.users_tree.yview)
        self.users_tree.configure(yscrollcommand=y_scrollbar.set)
        
        # Pack components
        y_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.users_tree.pack(fill="both", expand=True)
        
        return frame
    
    def show_add_user_form(self):
        # Clear form fields
        self.new_user_id.set("")
        self.new_password.set("")
        self.new_name.set("")
        self.new_role.set("faculty")
        self.new_email.set("")
        
        # Show form
        self.add_user_frame.pack(fill="x", expand=False, pady=10)
    
    def add_user(self):
        # Validate form data
        user_id = self.new_user_id.get().strip()
        password = self.new_password.get().strip()
        name = self.new_name.get().strip()
        role = self.new_role.get()
        email = self.new_email.get().strip()
        
        if not user_id:
            messagebox.showerror("Error", "User ID is required")
            return
        
        if not password:
            messagebox.showerror("Error", "Password is required")
            return
        
        if not name:
            messagebox.showerror("Error", "Name is required")
            return
        
        # Add user to database
        result = add_user(user_id, password, name, role, email)
        
        if result == -1:
            messagebox.showerror("Error", f"User ID '{user_id}' already exists")
            return
        
        # Hide form and refresh users list
        self.add_user_frame.pack_forget()
        self.refresh_users()
        messagebox.showinfo("Success", f"User '{name}' added successfully")
    
    def refresh_users(self):
        # Clear existing data
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
        
        # Get data from database
        role_filter = self.role_filter_var.get()
        users = get_all_users(role_filter)
        
        # Populate treeview
        for user in users:
            created_at = datetime.fromisoformat(user['created_at']).strftime("%Y-%m-%d %H:%M")
            self.users_tree.insert("", "end", values=(
                user['id'],
                user['user_id'],
                user['name'],
                user['role'],
                user['email'] or "",
                created_at
            ))
    
    def create_subject_management_tab(self):
        frame = ttk.Frame(self.content_area, padding=10)
        
        # Header section
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(header_frame, text="Subject Management", style='Header.TLabel').pack(side=tk.LEFT)
        
        # Add subject button
        add_subject_btn = ttk.Button(
            header_frame,
            text="Add Subject",
            command=self.show_add_subject_form,
            style='Primary.TButton'
        )
        add_subject_btn.pack(side=tk.RIGHT)
        
        # Add subject form (initially hidden)
        self.add_subject_frame = ttk.LabelFrame(frame, text="Add New Subject", padding=10)
        
        # Form fields
        form_grid = ttk.Frame(self.add_subject_frame)
        form_grid.pack(fill="x", expand=True)
        
        # Subject Code
        ttk.Label(form_grid, text="Subject Code:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.new_subject_code = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.new_subject_code, width=20).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Subject Name
        ttk.Label(form_grid, text="Subject Name:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.new_subject_name = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.new_subject_name, width=30).grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Form action buttons
        btn_frame = ttk.Frame(form_grid)
        btn_frame.grid(row=1, column=0, columnspan=4, sticky=tk.E, pady=10)
        
        ttk.Button(
            btn_frame, 
            text="Save", 
            command=self.add_subject, 
            style='Primary.TButton'
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            btn_frame, 
            text="Cancel", 
            command=lambda: self.add_subject_frame.pack_forget(), 
            style='Secondary.TButton'
        ).pack(side=tk.LEFT)
        
        # Subjects table
        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True, pady=(10, 0))
        
        # Create treeview
        columns = ("id", "subject_code", "subject_name", "created_at")
        self.subjects_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        # Define headings
        self.subjects_tree.heading("id", text="ID")
        self.subjects_tree.heading("subject_code", text="Subject Code")
        self.subjects_tree.heading("subject_name", text="Subject Name")
        self.subjects_tree.heading("created_at", text="Created At")
        
        # Define columns
        self.subjects_tree.column("id", width=50, anchor=tk.CENTER)
        self.subjects_tree.column("subject_code", width=150)
        self.subjects_tree.column("subject_name", width=300)
        self.subjects_tree.column("created_at", width=150)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.subjects_tree.yview)
        self.subjects_tree.configure(yscrollcommand=y_scrollbar.set)
        
        # Pack components
        y_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.subjects_tree.pack(fill="both", expand=True)
        
        return frame
    
    def show_add_subject_form(self):
        # Clear form fields
        self.new_subject_code.set("")
        self.new_subject_name.set("")
        
        # Show form
        self.add_subject_frame.pack(fill="x", expand=False, pady=10)
    
    def add_subject(self):
        # Validate form data
        subject_code = self.new_subject_code.get().strip().upper()
        subject_name = self.new_subject_name.get().strip()
        
        if not subject_code:
            messagebox.showerror("Error", "Subject Code is required")
            return
        
        if not subject_name:
            messagebox.showerror("Error", "Subject Name is required")
            return
        
        # Add subject to database
        result = add_subject(subject_code, subject_name)
        
        if result == -1:
            messagebox.showerror("Error", f"Subject Code '{subject_code}' already exists")
            return
        
        # Hide form and refresh subjects list
        self.add_subject_frame.pack_forget()
        self.refresh_subjects()
        messagebox.showinfo("Success", f"Subject '{subject_name}' added successfully")
    
    def refresh_subjects(self):
        # Clear existing data
        for item in self.subjects_tree.get_children():
            self.subjects_tree.delete(item)
        
        # Get data from database
        subjects = get_all_subjects()
        
        # Populate treeview
        for subject in subjects:
            created_at = datetime.fromisoformat(subject['created_at']).strftime("%Y-%m-%d %H:%M")
            self.subjects_tree.insert("", "end", values=(
                subject['id'],
                subject['subject_code'],
                subject['subject_name'],
                created_at
            ))
    
    def create_class_management_tab(self):
        frame = ttk.Frame(self.content_area, padding=10)
        
        # Header section
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(header_frame, text="Class Management", style='Header.TLabel').pack(side=tk.LEFT)
        
        # Add class button
        add_class_btn = ttk.Button(
            header_frame,
            text="Add Class",
            command=self.show_add_class_form,
            style='Primary.TButton'
        )
        add_class_btn.pack(side=tk.RIGHT)
        
        # Add class form (initially hidden)
        self.add_class_frame = ttk.LabelFrame(frame, text="Add New Class", padding=10)
        
        # Form fields
        form_grid = ttk.Frame(self.add_class_frame)
        form_grid.pack(fill="x", expand=True)
        
        # Class Name
        ttk.Label(form_grid, text="Class Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.new_class_name = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.new_class_name, width=20).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Semester
        ttk.Label(form_grid, text="Semester:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.new_semester = tk.StringVar()
        ttk.Spinbox(form_grid, from_=1, to=10, textvariable=self.new_semester, width=5).grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Section
        ttk.Label(form_grid, text="Section:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.new_section = tk.StringVar()
        ttk.Entry(form_grid, textvariable=self.new_section, width=10).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Form action buttons
        btn_frame = ttk.Frame(form_grid)
        btn_frame.grid(row=2, column=0, columnspan=4, sticky=tk.E, pady=10)
        
        ttk.Button(
            btn_frame, 
            text="Save", 
            command=self.add_class, 
            style='Primary.TButton'
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            btn_frame, 
            text="Cancel", 
            command=lambda: self.add_class_frame.pack_forget(), 
            style='Secondary.TButton'
        ).pack(side=tk.LEFT)
        
        # Classes table
        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True, pady=(10, 0))
        
        # Create treeview
        columns = ("id", "class_name", "semester", "section", "created_at")
        self.classes_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        # Define headings
        self.classes_tree.heading("id", text="ID")
        self.classes_tree.heading("class_name", text="Class Name")
        self.classes_tree.heading("semester", text="Semester")
        self.classes_tree.heading("section", text="Section")
        self.classes_tree.heading("created_at", text="Created At")
        
        # Define columns
        self.classes_tree.column("id", width=50, anchor=tk.CENTER)
        self.classes_tree.column("class_name", width=200)
        self.classes_tree.column("semester", width=100, anchor=tk.CENTER)
        self.classes_tree.column("section", width=100, anchor=tk.CENTER)
        self.classes_tree.column("created_at", width=150)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.classes_tree.yview)
        self.classes_tree.configure(yscrollcommand=y_scrollbar.set)
        
        # Pack components
        y_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.classes_tree.pack(fill="both", expand=True)
        
        return frame
    
    def show_add_class_form(self):
        # Clear form fields
        self.new_class_name.set("")
        self.new_semester.set("1")
        self.new_section.set("")
        
        # Show form
        self.add_class_frame.pack(fill="x", expand=False, pady=10)
    
    def add_class(self):
        # Validate form data
        class_name = self.new_class_name.get().strip()
        
        try:
            semester = int(self.new_semester.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Semester must be a number")
            return
        
        section = self.new_section.get().strip()
        
        if not class_name:
            messagebox.showerror("Error", "Class Name is required")
            return
        
        # Add class to database
        result = add_class(class_name, semester, section)
        
        if result == -1:
            messagebox.showerror("Error", f"Class with these details already exists")
            return
        
        # Hide form and refresh classes list
        self.add_class_frame.pack_forget()
        self.refresh_classes()
        messagebox.showinfo("Success", f"Class '{class_name}' added successfully")
    
    def refresh_classes(self):
        # Clear existing data
        for item in self.classes_tree.get_children():
            self.classes_tree.delete(item)
        
        # Get data from database
        classes = get_all_classes()
        
        # Populate treeview
        for cls in classes:
            created_at = datetime.fromisoformat(cls['created_at']).strftime("%Y-%m-%d %H:%M")
            self.classes_tree.insert("", "end", values=(
                cls['id'],
                cls['class_name'],
                cls['semester'],
                cls['section'] or "",
                created_at
            ))
    
    def create_assignment_management_tab(self):
        frame = ttk.Frame(self.content_area, padding=10)
        
        # Create notebook for faculty and student assignments
        notebook = ttk.Notebook(frame)
        notebook.pack(fill="both", expand=True)
        
        # Faculty assignments tab
        faculty_tab = ttk.Frame(notebook, padding=10)
        notebook.add(faculty_tab, text="Faculty Assignments")
        
        # Faculty assignment form
        faculty_form = ttk.LabelFrame(faculty_tab, text="Assign Faculty to Subject & Class", padding=10)
        faculty_form.pack(fill="x", expand=False, pady=(0, 10))
        
        faculty_grid = ttk.Frame(faculty_form)
        faculty_grid.pack(fill="x", expand=True)
        
        # Faculty dropdown
        ttk.Label(faculty_grid, text="Faculty:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.faculty_id_var = tk.StringVar()
        self.faculty_combo = ttk.Combobox(faculty_grid, textvariable=self.faculty_id_var, state="readonly", width=30)
        self.faculty_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Subject dropdown
        ttk.Label(faculty_grid, text="Subject:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.faculty_subject_var = tk.StringVar()
        self.subject_combo = ttk.Combobox(faculty_grid, textvariable=self.faculty_subject_var, state="readonly", width=30)
        self.subject_combo.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Class dropdown
        ttk.Label(faculty_grid, text="Class:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.faculty_class_var = tk.StringVar()
        self.class_combo = ttk.Combobox(faculty_grid, textvariable=self.faculty_class_var, state="readonly", width=30)
        self.class_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Assign button
        assign_btn_frame = ttk.Frame(faculty_grid)
        assign_btn_frame.grid(row=1, column=3, sticky=tk.E, pady=5)
        
        assign_faculty_btn = ttk.Button(
            assign_btn_frame,
            text="Assign",
            command=self.assign_faculty,
            style='Primary.TButton'
        )
        assign_faculty_btn.pack(padx=5)
        
        # Faculty assignments table
        faculty_table_frame = ttk.Frame(faculty_tab)
        faculty_table_frame.pack(fill="both", expand=True, pady=(10, 0))
        
        # Create treeview
        faculty_columns = ("id", "faculty", "subject", "class")
        self.faculty_assignments_tree = ttk.Treeview(faculty_table_frame, columns=faculty_columns, show="headings")
        
        # Define headings
        self.faculty_assignments_tree.heading("id", text="ID")
        self.faculty_assignments_tree.heading("faculty", text="Faculty")
        self.faculty_assignments_tree.heading("subject", text="Subject")
        self.faculty_assignments_tree.heading("class", text="Class")
        
        # Define columns
        self.faculty_assignments_tree.column("id", width=50, anchor=tk.CENTER)
        self.faculty_assignments_tree.column("faculty", width=200)
        self.faculty_assignments_tree.column("subject", width=200)
        self.faculty_assignments_tree.column("class", width=200)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(faculty_table_frame, orient=tk.VERTICAL, command=self.faculty_assignments_tree.yview)
        self.faculty_assignments_tree.configure(yscrollcommand=y_scrollbar.set)
        
        # Pack components
        y_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.faculty_assignments_tree.pack(fill="both", expand=True)
        
        # Student assignments tab
        student_tab = ttk.Frame(notebook, padding=10)
        notebook.add(student_tab, text="Student Assignments")
        
        # Student assignment form
        student_form = ttk.LabelFrame(student_tab, text="Assign Student to Class", padding=10)
        student_form.pack(fill="x", expand=False, pady=(0, 10))
        
        student_grid = ttk.Frame(student_form)
        student_grid.pack(fill="x", expand=True)
        
        # Student dropdown
        ttk.Label(student_grid, text="Student:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.student_id_var = tk.StringVar()
        self.student_combo = ttk.Combobox(student_grid, textvariable=self.student_id_var, state="readonly", width=30)
        self.student_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Class dropdown
        ttk.Label(student_grid, text="Class:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.student_class_var = tk.StringVar()
        self.student_class_combo = ttk.Combobox(student_grid, textvariable=self.student_class_var, state="readonly", width=30)
        self.student_class_combo.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Assign button
        student_btn_frame = ttk.Frame(student_grid)
        student_btn_frame.grid(row=1, column=3, sticky=tk.E, pady=5)
        
        assign_student_btn = ttk.Button(
            student_btn_frame,
            text="Assign",
            command=self.assign_student,
            style='Primary.TButton'
        )
        assign_student_btn.pack(padx=5)
        
        # Student assignments table
        student_table_frame = ttk.Frame(student_tab)
        student_table_frame.pack(fill="both", expand=True, pady=(10, 0))
        
        # Create treeview
        student_columns = ("id", "student", "class")
        self.student_assignments_tree = ttk.Treeview(student_table_frame, columns=student_columns, show="headings")
        
        # Define headings
        self.student_assignments_tree.heading("id", text="ID")
        self.student_assignments_tree.heading("student", text="Student")
        self.student_assignments_tree.heading("class", text="Class")
        
        # Define columns
        self.student_assignments_tree.column("id", width=50, anchor=tk.CENTER)
        self.student_assignments_tree.column("student", width=200)
        self.student_assignments_tree.column("class", width=200)
        
        # Add scrollbars
        student_y_scrollbar = ttk.Scrollbar(student_table_frame, orient=tk.VERTICAL, command=self.student_assignments_tree.yview)
        self.student_assignments_tree.configure(yscrollcommand=student_y_scrollbar.set)
        
        # Pack components
        student_y_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.student_assignments_tree.pack(fill="both", expand=True)
        
        return frame
    
    def refresh_assignments(self):
        # Refresh faculty dropdown
        faculty_list = get_all_users('faculty')
        self.faculty_options = {f"{user['name']} ({user['user_id']})": user['id'] for user in faculty_list}
        self.faculty_combo['values'] = list(self.faculty_options.keys())
        
        # Refresh student dropdown
        student_list = get_all_users('student')
        self.student_options = {f"{user['name']} ({user['user_id']})": user['id'] for user in student_list}
        self.student_combo['values'] = list(self.student_options.keys())
        
        # Refresh subject dropdown
        subject_list = get_all_subjects()
        self.subject_options = {f"{subject['subject_name']} ({subject['subject_code']})": subject['id'] for subject in subject_list}
        self.subject_combo['values'] = list(self.subject_options.keys())
        
        # Refresh class dropdown
        class_list = get_all_classes()
        class_names = []
        self.class_options = {}
        
        for cls in class_list:
            display = f"{cls['class_name']} - Sem {cls['semester']}" + (f", {cls['section']}" if cls['section'] else "")
            class_names.append(display)
            self.class_options[display] = cls['id']
        
        self.class_combo['values'] = class_names
        self.student_class_combo['values'] = class_names
    
    def assign_faculty(self):
        faculty_display = self.faculty_id_var.get()
        subject_display = self.faculty_subject_var.get()
        class_display = self.faculty_class_var.get()
        
        if not faculty_display or not subject_display or not class_display:
            messagebox.showerror("Error", "All fields are required")
            return
        
        # Get IDs from selected options
        faculty_id = self.faculty_options[faculty_display]
        subject_id = self.subject_options[subject_display]
        class_id = self.class_options[class_display]
        
        # Assign faculty in database
        result = assign_faculty(faculty_id, subject_id, class_id)
        
        if result == -1:
            messagebox.showerror("Error", "This faculty assignment already exists")
            return
        
        messagebox.showinfo("Success", "Faculty assigned successfully")
        self.refresh_assignments()
    
    def assign_student(self):
        student_display = self.student_id_var.get()
        class_display = self.student_class_var.get()
        
        if not student_display or not class_display:
            messagebox.showerror("Error", "All fields are required")
            return
        
        # Get IDs from selected options
        student_id = self.student_options[student_display]
        class_id = self.class_options[class_display]
        
        # Assign student in database
        result = assign_student_to_class(student_id, class_id)
        
        if result == -1:
            messagebox.showerror("Error", "This student is already assigned to this class")
            return
        
        messagebox.showinfo("Success", "Student assigned to class successfully")
        self.refresh_assignments()
    
    def create_reports_tab(self):
        frame = ttk.Frame(self.content_area, padding=10)
        
        # Header section
        ttk.Label(frame, text="Attendance Reports", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        # Report filters
        filters_frame = ttk.LabelFrame(frame, text="Filters", padding=10)
        filters_frame.pack(fill="x", pady=(0, 10))
        
        filters_grid = ttk.Frame(filters_frame)
        filters_grid.pack(fill="x", expand=True)
        
        # Student filter
        ttk.Label(filters_grid, text="Student:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.report_student_var = tk.StringVar()
        self.report_student_combo = ttk.Combobox(filters_grid, textvariable=self.report_student_var, state="readonly", width=30)
        self.report_student_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # View report button
        ttk.Button(
            filters_grid,
            text="View Report",
            command=self.view_student_report,
            style='Primary.TButton'
        ).grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        
        # Report content area
        self.report_content = ttk.Frame(frame)
        self.report_content.pack(fill="both", expand=True, pady=10)
        
        # Create initial message
        self.report_placeholder = ttk.Label(
            self.report_content,
            text="Select a student and click 'View Report' to view attendance statistics",
            anchor=tk.CENTER
        )
        self.report_placeholder.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        return frame
    
    def refresh_reports(self):
        # Refresh student dropdown for reports
        student_list = get_all_users('student')
        self.report_student_options = {f"{user['name']} ({user['user_id']})": user['id'] for user in student_list}
        self.report_student_combo['values'] = list(self.report_student_options.keys())
    
    def view_student_report(self):
        student_display = self.report_student_var.get()
        
        if not student_display:
            messagebox.showerror("Error", "Please select a student")
            return
        
        # Get student ID
        student_id = self.report_student_options[student_display]
        
        # Clear previous report content
        for widget in self.report_content.winfo_children():
            widget.destroy()
        
        # Create scrollable canvas for report
        canvas_frame = ttk.Frame(self.report_content)
        canvas_frame.pack(fill="both", expand=True)
        
        # Add canvas with scrollbar
        canvas = tk.Canvas(canvas_frame)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        report_frame = ttk.Frame(canvas)
        
        # Configure canvas and scrollbar
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        
        # Create a window inside the canvas
        canvas.create_window((0, 0), window=report_frame, anchor="nw")
        report_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        # Get attendance statistics
        stats = calculate_attendance_stats(student_id)
        
        if not stats['overall']['total']:
            # No attendance records
            ttk.Label(
                report_frame, 
                text="No attendance records found for this student",
                style='Subheader.TLabel'
            ).pack(pady=50)
            return
        
        # Display student name
        student_info = [u for u in get_all_users() if u['id'] == student_id][0]
        ttk.Label(
            report_frame, 
            text=f"Attendance Report for {student_info['name']} ({student_info['user_id']})",
            style='Header.TLabel'
        ).pack(anchor=tk.W, pady=(0, 20))
        
        # Overall attendance card
        overall_frame = ttk.LabelFrame(report_frame, text="Overall Attendance", padding=10)
        overall_frame.pack(fill="x", pady=(0, 20))
        
        percentage = stats['overall']['percentage']
        percentage_color = "green" if percentage >= 75 else "red"
        
        overall_grid = ttk.Frame(overall_frame)
        overall_grid.pack(fill="x")
        
        ttk.Label(overall_grid, text=f"{percentage:.2f}%", font=('Arial', 24, 'bold'), foreground=percentage_color).grid(row=0, column=0, rowspan=2, padx=(0, 20))
        
        ttk.Label(overall_grid, text=f"Classes Attended: {stats['overall']['present']} out of {stats['overall']['total']}").grid(row=0, column=1, sticky=tk.W)
        ttk.Label(overall_grid, text=f"Total Subjects: {len(stats['subjects'])}").grid(row=1, column=1, sticky=tk.W)
        
        # Subject-wise attendance
        subjects_frame = ttk.LabelFrame(report_frame, text="Subject-wise Attendance", padding=10)
        subjects_frame.pack(fill="x", pady=(0, 20))
        
        for i, (subject_code, subject) in enumerate(stats['subjects'].items()):
            subject_frame = ttk.Frame(subjects_frame, relief="groove", borderwidth=1)
            subject_frame.pack(fill="x", pady=5)
            
            subject_percentage = subject['percentage']
            subject_color = "green" if subject_percentage >= 75 else "red"
            
            ttk.Label(subject_frame, text=subject['name'], style='Subheader.TLabel').grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
            ttk.Label(subject_frame, text=f"{subject_percentage:.2f}%", foreground=subject_color).grid(row=0, column=1, sticky=tk.E, padx=10)
            
            details_frame = ttk.Frame(subject_frame)
            details_frame.grid(row=1, column=0, columnspan=2, sticky=tk.EW, padx=10, pady=5)
            
            ttk.Label(details_frame, text=f"Total Classes: {subject['total']}").pack(side=tk.LEFT, padx=10)
            ttk.Label(details_frame, text=f"Present: {subject['present']}").pack(side=tk.LEFT, padx=10)
            ttk.Label(details_frame, text=f"Absent: {subject['absent']}").pack(side=tk.LEFT, padx=10)
            ttk.Label(details_frame, text=f"Late: {subject['late']}").pack(side=tk.LEFT, padx=10)
        
                # Attendance records
        records_frame = ttk.LabelFrame(report_frame, text="Recent Attendance Records", padding=10)
        records_frame.pack(fill="x", expand=True)
        
        # Create treeview for records
        columns = ("date", "subject", "status")
        records_tree = ttk.Treeview(records_frame, columns=columns, show="headings")
        
        # Define headings
        records_tree.heading("date", text="Date")
        records_tree.heading("subject", text="Subject")
        records_tree.heading("status", text="Status")
        
        # Define columns
        records_tree.column("date", width=150)
        records_tree.column("subject", width=200)
        records_tree.column("status", width=100)
        
        # Add records
        attendance_records = get_student_attendance(student_id)
        
        for record in attendance_records[:20]:  # Show only the 20 most recent records
            status_text = record['status'].capitalize()
            date_text = record['date']
            records_tree.insert("", "end", values=(
                date_text,
                f"{record['subject_name']} ({record['subject_code']})",
                status_text
            ))
        
        records_tree.pack(fill="x", expand=True)


# =============== FACULTY DASHBOARD ===============

class FacultyDashboard(tk.Frame):
    def __init__(self, parent, user_data, logout_callback):
        super().__init__(parent)
        self.parent = parent
        self.user_data = user_data
        self.logout_callback = logout_callback
        
        self.configure_styles()
        self.create_widgets()
        self.pack(fill="both", expand=True)
        
        # Default to mark attendance tab
        self.show_tab("mark")
    
    def configure_styles(self):
        style = ttk.Style()
        
        # Configure label styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Subheader.TLabel', font=('Arial', 12, 'bold'))
        
        # Configure button styles
        style.configure('NavButton.TButton', font=('Arial', 11))
        style.configure('Primary.TButton', font=('Arial', 11))
        style.configure('Secondary.TButton', font=('Arial', 11))
        
        # Configure treeview
        style.configure('Treeview.Heading', font=('Arial', 11, 'bold'))
    
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True)
        
        # Top navigation bar
        nav_frame = ttk.Frame(main_frame, padding=10, relief='ridge', borderwidth=1)
        nav_frame.pack(fill="x")
        
        # Title and user info
        title_frame = ttk.Frame(nav_frame)
        title_frame.pack(side=tk.LEFT)
        
        ttk.Label(title_frame, text="College Attendance Management System", style='Title.TLabel').pack(anchor=tk.W)
        ttk.Label(title_frame, text=f"Logged in as: {self.user_data['name']} (Faculty)").pack(anchor=tk.W)
        
        # Logout button
        logout_btn = ttk.Button(nav_frame, text="Logout", command=self.logout_callback, style='NavButton.TButton')
        logout_btn.pack(side=tk.RIGHT)
        
        # Content area with sidebar and main content
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill="both", expand=True, pady=10)
        
        # Sidebar
        sidebar_frame = ttk.Frame(content_frame, width=200, relief='ridge', borderwidth=1)
        sidebar_frame.pack(side=tk.LEFT, fill="y", padx=(0, 10))
        sidebar_frame.pack_propagate(False)  # Prevent shrinking
        
        # Sidebar title
        ttk.Label(sidebar_frame, text="Faculty Panel", style='Subheader.TLabel').pack(anchor=tk.W, padx=10, pady=10)
        
        # Sidebar navigation buttons
        self.nav_buttons = {}
        
        nav_options = [
            ("Mark Attendance", "mark"),
            ("My Assignments", "assignments"),
            ("Attendance Reports", "reports")
        ]
        
        for text, tab_id in nav_options:
            btn = ttk.Button(
                sidebar_frame,
                text=text,
                command=lambda t=tab_id: self.show_tab(t),
                style='NavButton.TButton',
                width=25
            )
            btn.pack(fill="x", padx=5, pady=2)
            self.nav_buttons[tab_id] = btn
        
        # Main content area
        self.content_area = ttk.Frame(content_frame)
        self.content_area.pack(side=tk.RIGHT, fill="both", expand=True)
        
        # Create all tab frames
        self.tab_frames = {
            "mark": self.create_mark_attendance_tab(),
            "assignments": self.create_assignments_tab(),
            "reports": self.create_reports_tab()
        }
    
    def show_tab(self, tab_id):
        # Hide all frames
        for frame in self.tab_frames.values():
            frame.pack_forget()
        
        # Reset all button styles
        for btn in self.nav_buttons.values():
            btn.configure(style='NavButton.TButton')
        
        # Show selected frame
        self.tab_frames[tab_id].pack(fill="both", expand=True)
        
        # Highlight selected button
        self.nav_buttons[tab_id].configure(style='Primary.TButton')
        
        # Refresh tab data
        if tab_id == "mark":
            self.refresh_mark_attendance()
        elif tab_id == "assignments":
            self.refresh_assignments()
        elif tab_id == "reports":
            self.refresh_reports()
    
    def create_mark_attendance_tab(self):
        frame = ttk.Frame(self.content_area, padding=10)
        
        # Header
        ttk.Label(frame, text="Mark Attendance", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        # Assignment selection
        selection_frame = ttk.LabelFrame(frame, text="Class & Subject Selection", padding=10)
        selection_frame.pack(fill="x", pady=(0, 10))
        
        selection_grid = ttk.Frame(selection_frame)
        selection_grid.pack(fill="x", expand=True)
        
        # Assignment dropdown
        ttk.Label(selection_grid, text="Select Class & Subject:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.assignment_var = tk.StringVar()
        self.assignment_combo = ttk.Combobox(selection_grid, textvariable=self.assignment_var, state="readonly", width=40)
        self.assignment_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.assignment_combo.bind("<<ComboboxSelected>>", self.on_assignment_selected)
        
        # Date selection
        ttk.Label(selection_grid, text="Date:").grid(row=0, column=2, sticky=tk.W, padx=(20, 5), pady=5)
        self.date_var = tk.StringVar(value=date.today().isoformat())
        date_entry = DateEntry(selection_grid, textvariable=self.date_var, width=12, date_pattern='yyyy-mm-dd')
        date_entry.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)
        
        # Students list and attendance marking
        self.students_frame = ttk.LabelFrame(frame, text="Students", padding=10)
        # Pack this only when assignment is selected
        
        # Success message (hidden initially)
        self.success_var = tk.StringVar()
        self.success_label = ttk.Label(
            frame, 
            textvariable=self.success_var, 
            foreground="green",
            font=('Arial', 12)
        )
        self.success_label.pack(anchor=tk.CENTER, pady=10)
        self.success_label.pack_forget()  # Hide initially
        
        # Placeholder when no assignment is selected
        self.placeholder_label = ttk.Label(
            frame,
            text="Select a class and subject to mark attendance",
            font=('Arial', 12),
            foreground="gray"
        )
        self.placeholder_label.pack(expand=True, anchor=tk.CENTER, pady=50)
        
        return frame
    
    def create_assignments_tab(self):
        frame = ttk.Frame(self.content_area, padding=10)
        
        # Header
        ttk.Label(frame, text="My Assignments", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        # Assignments table
        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True)
        
        # Create treeview
        columns = ("id", "subject", "class", "semester", "section")
        self.assignments_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        # Define headings
        self.assignments_tree.heading("id", text="ID")
        self.assignments_tree.heading("subject", text="Subject")
        self.assignments_tree.heading("class", text="Class")
        self.assignments_tree.heading("semester", text="Semester")
        self.assignments_tree.heading("section", text="Section")
        
        # Define columns
        self.assignments_tree.column("id", width=50, anchor=tk.CENTER)
        self.assignments_tree.column("subject", width=200)
        self.assignments_tree.column("class", width=200)
        self.assignments_tree.column("semester", width=100, anchor=tk.CENTER)
        self.assignments_tree.column("section", width=100, anchor=tk.CENTER)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.assignments_tree.yview)
        self.assignments_tree.configure(yscrollcommand=y_scrollbar.set)
        
        # Pack components
        y_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.assignments_tree.pack(fill="both", expand=True)
        
        return frame
    
    def create_reports_tab(self):
        frame = ttk.Frame(self.content_area, padding=10)
        
        # Header
        ttk.Label(frame, text="Attendance Reports", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 10))
        
        # Report filters
        filters_frame = ttk.LabelFrame(frame, text="Filters", padding=10)
        filters_frame.pack(fill="x", pady=(0, 10))
        
        filters_grid = ttk.Frame(filters_frame)
        filters_grid.pack(fill="x", expand=True)
        
        # Assignment filter
        ttk.Label(filters_grid, text="Class & Subject:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.report_assignment_var = tk.StringVar()
        self.report_assignment_combo = ttk.Combobox(filters_grid, textvariable=self.report_assignment_var, state="readonly", width=40)
        self.report_assignment_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # View report button
        ttk.Button(
            filters_grid,
            text="View Report",
            command=self.view_class_report,
            style='Primary.TButton'
        ).grid(row=0, column=2, padx=5, pady=5)
        
        # Report content frame
        self.report_content = ttk.Frame(frame)
        self.report_content.pack(fill="both", expand=True, pady=10)
        
        # Create initial message
        self.report_placeholder = ttk.Label(
            self.report_content,
            text="Select a class and subject to view attendance statistics",
            font=('Arial', 12),
            foreground="gray"
        )
        self.report_placeholder.pack(expand=True, anchor=tk.CENTER, pady=50)
        
        return frame
    
    def refresh_mark_attendance(self):
        # Get faculty's assignments
        assignments = get_faculty_assignments(self.user_data['id'])
        
        # Reset variables
        self.assignments = assignments
        self.assignment_options = {}
        
        # Fill assignment dropdown
        assignment_display = []
        for assignment in assignments:
            display = f"{assignment['class_name']} - {assignment['subject_name']} ({assignment['subject_code']})"
            assignment_display.append(display)
            self.assignment_options[display] = assignment
        
        self.assignment_combo['values'] = assignment_display
        
        # Hide students frame and show placeholder
        self.students_frame.pack_forget()
        self.placeholder_label.pack(expand=True, anchor=tk.CENTER, pady=50)
        self.success_label.pack_forget()
        
        # Clear assignment selection
        self.assignment_var.set("")
    
    def refresh_assignments(self):
        # Clear existing data
        for item in self.assignments_tree.get_children():
            self.assignments_tree.delete(item)
        
        # Get faculty's assignments
        assignments = get_faculty_assignments(self.user_data['id'])
        
        # Populate treeview
        for assignment in assignments:
            self.assignments_tree.insert("", "end", values=(
                assignment['id'],
                f"{assignment['subject_name']} ({assignment['subject_code']})",
                assignment['class_name'],
                assignment['semester'],
                assignment['section'] or ""
            ))
    
    def refresh_reports(self):
        # Get faculty's assignments
        assignments = get_faculty_assignments(self.user_data['id'])
        
        # Reset variables
        self.report_assignments = assignments
        self.report_assignment_options = {}
        
        # Fill assignment dropdown
        assignment_display = []
        for assignment in assignments:
            display = f"{assignment['class_name']} - {assignment['subject_name']} ({assignment['subject_code']})"
            assignment_display.append(display)
            self.report_assignment_options[display] = assignment
        
        self.report_assignment_combo['values'] = assignment_display
    
    def on_assignment_selected(self, event=None):
        assignment_display = self.assignment_var.get()
        
        if not assignment_display:
            return
        
        # Get selected assignment
        assignment = self.assignment_options[assignment_display]
        
        # Get students in the class
        students = get_class_students(assignment['class_id'])
        
        # Hide placeholder
        self.placeholder_label.pack_forget()
        self.success_label.pack_forget()
        
        # Clear students frame
        self.students_frame.pack_forget()
        self.students_frame = ttk.LabelFrame(self.tab_frames["mark"], text="Students", padding=10)
        self.students_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        if not students:
            # No students in class
            ttk.Label(
                self.students_frame,
                text="No students found in this class",
                font=('Arial', 12),
                foreground="gray"
            ).pack(expand=True, anchor=tk.CENTER, pady=50)
            return
        
        # Create student attendance form
        self.student_status = {}
        
        # Create a canvas with scrollbar for many students
        canvas_frame = ttk.Frame(self.students_frame)
        canvas_frame.pack(fill="both", expand=True)
        
        canvas = tk.Canvas(canvas_frame)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        students_list_frame = ttk.Frame(canvas)
        
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.create_window((0, 0), window=students_list_frame, anchor="nw")
        students_list_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        # Create header row
        header_frame = ttk.Frame(students_list_frame)
        header_frame.pack(fill="x", pady=5)
        
        ttk.Label(header_frame, text="Student ID", width=15, font=('Arial', 11, 'bold')).pack(side=tk.LEFT, padx=5)
        ttk.Label(header_frame, text="Name", width=30, font=('Arial', 11, 'bold')).pack(side=tk.LEFT, padx=5)
        ttk.Label(header_frame, text="Status", width=15, font=('Arial', 11, 'bold')).pack(side=tk.LEFT, padx=5)
        
        # Create row for each student
        for student in students:
            row_frame = ttk.Frame(students_list_frame)
            row_frame.pack(fill="x", pady=2)
            
            ttk.Label(row_frame, text=student['user_id'], width=15).pack(side=tk.LEFT, padx=5)
            ttk.Label(row_frame, text=student['name'], width=30).pack(side=tk.LEFT, padx=5)
            
            status_var = tk.StringVar(value="present")
            self.student_status[student['id']] = status_var
            
            status_combo = ttk.Combobox(
                row_frame, 
                textvariable=status_var,
                values=["present", "absent", "late"],
                state="readonly",
                width=10
            )
            status_combo.pack(side=tk.LEFT, padx=5)
        
        # Submit button
        btn_frame = ttk.Frame(self.students_frame)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(
            btn_frame,
            text="Submit Attendance",
            command=self.submit_attendance,
            style='Primary.TButton'
        ).pack(side=tk.RIGHT)
        
        # Store current selection for submission
        self.current_assignment = assignment
    
    def submit_attendance(self):
        if not hasattr(self, 'current_assignment'):
            return
        
        # Get selected date
        selected_date = self.date_var.get()
        
        # Mark attendance for each student
        for student_id, status_var in self.student_status.items():
            mark_attendance(
                student_id=student_id,
                subject_id=self.current_assignment['subject_id'],
                class_id=self.current_assignment['class_id'],
                date=selected_date,
                status=status_var.get(),
                marked_by=self.user_data['id']
            )
        
        # Show success message
        self.success_var.set("Attendance marked successfully!")
        self.success_label.pack(anchor=tk.CENTER, pady=10)
        
        # Hide students form
        self.students_frame.pack_forget()
        
        # Reset assignment selection
        self.assignment_var.set("")
    
    def view_class_report(self):
        assignment_display = self.report_assignment_var.get()
        
        if not assignment_display:
            messagebox.showerror("Error", "Please select a class and subject")
            return
        
        # Get selected assignment
        assignment = self.report_assignment_options[assignment_display]
        
        # Clear report content
        for widget in self.report_content.winfo_children():
            widget.destroy()
        
        # Get students in the class
        students = get_class_students(assignment['class_id'])
        
        if not students:
            ttk.Label(
                self.report_content,
                text="No students found in this class",
                font=('Arial', 12),
                foreground="gray"
            ).pack(expand=True, anchor=tk.CENTER, pady=50)
            return
        
        # Header
        ttk.Label(
            self.report_content,
            text=f"Attendance Report for {assignment['class_name']} - {assignment['subject_name']} ({assignment['subject_code']})",
            style='Subheader.TLabel'
        ).pack(anchor=tk.W, pady=(0, 10))
        
        # Create attendance table
        table_frame = ttk.Frame(self.report_content)
        table_frame.pack(fill="both", expand=True)
        
        columns = ("id", "student_id", "name", "total", "present", "absent", "late", "percentage")
        report_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        # Define headings
        report_tree.heading("id", text="ID")
        report_tree.heading("student_id", text="Student ID")
        report_tree.heading("name", text="Name")
        report_tree.heading("total", text="Total Classes")
        report_tree.heading("present", text="Present")
        report_tree.heading("absent", text="Absent")
        report_tree.heading("late", text="Late")
        report_tree.heading("percentage", text="Percentage")
        
        # Define columns
        report_tree.column("id", width=50, anchor=tk.CENTER)
        report_tree.column("student_id", width=100)
        report_tree.column("name", width=150)
        report_tree.column("total", width=100, anchor=tk.CENTER)
        report_tree.column("present", width=100, anchor=tk.CENTER)
        report_tree.column("absent", width=100, anchor=tk.CENTER)
        report_tree.column("late", width=100, anchor=tk.CENTER)
        report_tree.column("percentage", width=100, anchor=tk.CENTER)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=report_tree.yview)
        report_tree.configure(yscrollcommand=y_scrollbar.set)
        
        # Pack components
        y_scrollbar.pack(side=tk.RIGHT, fill="y")
        report_tree.pack(fill="both", expand=True)
        
        # For each student, calculate attendance stats and add to table
        for student in students:
            # Calculate attendance for specific subject and class
            stats = calculate_attendance_stats(student['id'])
            
            # Look for subject stats
            subject_code = assignment['subject_code']
            if subject_code in stats['subjects']:
                subject_stats = stats['subjects'][subject_code]
                total = subject_stats['total']
                present = subject_stats['present']
                absent = subject_stats['absent']
                late = subject_stats['late']
                percentage = subject_stats['percentage']
            else:
                total = 0
                present = 0
                absent = 0
                late = 0
                percentage = 0
            
            report_tree.insert("", "end", values=(
                student['id'],
                student['user_id'],
                student['name'],
                total,
                present,
                absent,
                late,
                f"{percentage:.2f}%"
            ))

# =============== STUDENT DASHBOARD ===============

class StudentDashboard(tk.Frame):
    def __init__(self, parent, user_data, logout_callback):
        super().__init__(parent)
        self.parent = parent
        self.user_data = user_data
        self.logout_callback = logout_callback
        
        self.configure_styles()
        self.create_widgets()
        self.pack(fill="both", expand=True)
        
        # Load attendance data
        self.load_attendance_data()
    
    def configure_styles(self):
        style = ttk.Style()
        
        # Configure label styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Subheader.TLabel', font=('Arial', 12, 'bold'))
        
        # Configure button styles
        style.configure('NavButton.TButton', font=('Arial', 11))
        
        # Configure treeview
        style.configure('Treeview.Heading', font=('Arial', 11, 'bold'))
    
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(fill="both", expand=True)
        
        # Top navigation bar
        nav_frame = ttk.Frame(main_frame, padding=10, relief='ridge', borderwidth=1)
        nav_frame.pack(fill="x")
        
        # Title and user info
        title_frame = ttk.Frame(nav_frame)
        title_frame.pack(side=tk.LEFT)
        
        ttk.Label(title_frame, text="College Attendance Management System", style='Title.TLabel').pack(anchor=tk.W)
        ttk.Label(title_frame, text=f"Logged in as: {self.user_data['name']} (Student)").pack(anchor=tk.W)
        
        # Logout button
        logout_btn = ttk.Button(nav_frame, text="Logout", command=self.logout_callback, style='NavButton.TButton')
        logout_btn.pack(side=tk.RIGHT)
        
        # Content area
        content_frame = ttk.Frame(main_frame, padding=20)
        content_frame.pack(fill="both", expand=True, pady=10)
        
        # Attendance summary section
        ttk.Label(content_frame, text="My Attendance Summary", style='Header.TLabel').pack(anchor=tk.W, pady=(0, 20))
        
        # Loading indicator (shown initially, hidden when data loads)
        self.loading_label = ttk.Label(content_frame, text="Loading attendance data...", font=('Arial', 12))
        self.loading_label.pack(anchor=tk.CENTER, pady=20)
        
        # Overall Attendance Card (initially hidden)
        self.overall_frame = ttk.LabelFrame(content_frame, text="Overall Attendance", padding=15)
        
        # Subject-wise Attendance Section (initially hidden)
        self.subjects_frame = ttk.LabelFrame(content_frame, text="Subject-wise Attendance", padding=15)
        
        # Recent Attendance Records (initially hidden)
        self.records_frame = ttk.LabelFrame(content_frame, text="Recent Attendance Records", padding=15)
    
    def load_attendance_data(self):
        # Calculate attendance statistics
        self.stats = calculate_attendance_stats(self.user_data['id'])
        
        # Hide loading indicator
        self.loading_label.pack_forget()
        
        # No attendance records case
        if not self.stats['overall']['total']:
            no_records = ttk.Label(
                self.master,
                text="No attendance records found",
                font=('Arial', 14),
                foreground="gray"
            )
            no_records.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
            return
        
        # Display overall attendance
        self.overall_frame.pack(fill="x", pady=(0, 20))
        
        overall_grid = ttk.Frame(self.overall_frame)
        overall_grid.pack(fill="x", expand=True)
        
        percentage = self.stats['overall']['percentage']
        percentage_color = "green" if percentage >= 75 else "red"
        
        ttk.Label(
            overall_grid, 
            text=f"{percentage:.2f}%", 
            font=('Arial', 24, 'bold'), 
            foreground=percentage_color
        ).grid(row=0, column=0, rowspan=2, padx=(0, 20))
        
        ttk.Label(
            overall_grid, 
            text=f"Classes Attended: {self.stats['overall']['present']} out of {self.stats['overall']['total']}"
        ).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(
            overall_grid, 
            text=f"Total Subjects: {len(self.stats['subjects'])}"
        ).grid(row=1, column=1, sticky=tk.W)
        
        # Display subject-wise attendance
        self.subjects_frame.pack(fill="x", pady=(0, 20))
        
        # Create canvas for scrolling if many subjects
        canvas_frame = ttk.Frame(self.subjects_frame)
        canvas_frame.pack(fill="both", expand=True)
        
        canvas = tk.Canvas(canvas_frame, height=200)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        subjects_container = ttk.Frame(canvas)
        
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        canvas.create_window((0, 0), window=subjects_container, anchor="nw", tags="subjects_container")
        subjects_container.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        # Add each subject
        row = 0
        for subject_code, subject in self.stats['subjects'].items():
            subject_frame = ttk.Frame(subjects_container, padding=5)
            subject_frame.grid(row=row, column=0, sticky="ew", pady=5)
            
            subject_percentage = subject['percentage']
            subject_color = "green" if subject_percentage >= 75 else "red"
            
            # Create a progress bar-like frame
            bar_width = 400
            progress_width = int((bar_width * subject_percentage) / 100)
            
            bar_frame = ttk.Frame(subject_frame, width=bar_width, height=30, relief="sunken", borderwidth=1)
            bar_frame.pack(side=tk.LEFT, padx=(0, 10))
            bar_frame.pack_propagate(False)
            
            progress_frame = ttk.Frame(bar_frame, width=progress_width, height=30, style='progress.TFrame')
            progress_frame.pack(side=tk.LEFT, anchor=tk.W, fill="y")
            
            # Override style for progress frame
            if subject_percentage >= 75:
                progress_frame.configure(background="green")
            else:
                progress_frame.configure(background="red")
            
            # Add percentage text on top of progress bar
            percentage_label = ttk.Label(
                bar_frame, 
                text=f"{subject_percentage:.2f}%", 
                background="white",
                foreground=subject_color,
                font=('Arial', 12, 'bold')
            )
            percentage_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
            
            # Subject details
            details_frame = ttk.Frame(subject_frame)
            details_frame.pack(side=tk.LEFT, fill="both")
            
            ttk.Label(details_frame, text=f"{subject['name']} ({subject_code})", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
            
            stats_frame = ttk.Frame(details_frame)
            stats_frame.pack(fill="x", expand=True)
            
            ttk.Label(stats_frame, text=f"Total: {subject['total']}").pack(side=tk.LEFT, padx=5)
            ttk.Label(stats_frame, text=f"Present: {subject['present']}").pack(side=tk.LEFT, padx=5)
            ttk.Label(stats_frame, text=f"Absent: {subject['absent']}").pack(side=tk.LEFT, padx=5)
            ttk.Label(stats_frame, text=f"Late: {subject['late']}").pack(side=tk.LEFT, padx=5)
            
            row += 1
        
        # Display attendance records
        self.records_frame.pack(fill="both", expand=True)
        
        # Create treeview for records
        table_frame = ttk.Frame(self.records_frame)
        table_frame.pack(fill="both", expand=True, pady=10)
        
        columns = ("date", "subject", "class", "status")
        self.records_tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        # Define headings
        self.records_tree.heading("date", text="Date")
        self.records_tree.heading("subject", text="Subject")
        self.records_tree.heading("class", text="Class")
        self.records_tree.heading("status", text="Status")
        
        # Define columns
        self.records_tree.column("date", width=120)
        self.records_tree.column("subject", width=200)
        self.records_tree.column("class", width=150)
        self.records_tree.column("status", width=100)
        
        # Add scrollbar
        y_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.records_tree.yview)
        self.records_tree.configure(yscrollcommand=y_scrollbar.set)
        
        y_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.records_tree.pack(fill="both", expand=True)
        
        # Fetch and display records
        attendance_records = get_student_attendance(self.user_data['id'])
        
        for record in attendance_records:
            status_text = record['status'].capitalize()
            date_text = record['date']
            
            self.records_tree.insert("", "end", values=(
                date_text,
                f"{record['subject_name']} ({record['subject_code']})",
                record['class_name'],
                status_text
            ))

# =============== MAIN APPLICATION ===============

class AttendanceManagementSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("College Attendance Management System")
        self.root.geometry("1200x700")
        self.root.resizable(True, True)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Initialize database
        db_path = "attendance.db"
        initialize_database(db_path)
        
        # Start with login screen
        self.current_screen = None
        self.show_login_screen()
    
    def show_login_screen(self):
        if self.current_screen:
            self.current_screen.destroy()
        
        self.current_screen = LoginScreen(self.root, self.on_login_success)
    
    def on_login_success(self, user_data):
        if self.current_screen:
            self.current_screen.destroy()
        
        if user_data['role'] == 'admin':
            self.current_screen = AdminDashboard(self.root, user_data, self.show_login_screen)
        elif user_data['role'] == 'faculty':
            self.current_screen = FacultyDashboard(self.root, user_data, self.show_login_screen)
        elif user_data['role'] == 'student':
            self.current_screen = StudentDashboard(self.root, user_data, self.show_login_screen)
    
    def on_close(self):
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = AttendanceManagementSystem(root)
    root.mainloop()