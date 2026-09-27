import sqlite3
import pickle
import os
import uuid

from datetime import datetime, timedelta

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    send_from_directory,
    session
)

from werkzeug.utils import secure_filename
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "datadharma-development-key"
)


# ============================================================
# DATABASE
# ============================================================

DATABASE = "datadharma.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
# FILE UPLOAD SETTINGS
# ============================================================

UPLOAD_FOLDER = "uploads"

ALLOWED_EXTENSIONS = {
    "pdf",
    "jpg",
    "jpeg",
    "png",
    "docx"
}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ============================================================
# AI MODEL
# ============================================================

try:

    with open("risk_model.pkl", "rb") as file:
        risk_model = pickle.load(file)

    print("AI risk model loaded successfully.")

except FileNotFoundError:

    risk_model = None

    print(
        "WARNING: risk_model.pkl was not found."
    )

except Exception as exc:

    risk_model = None

    print(
        f"WARNING: Could not load AI model: {exc}"
    )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    # --------------------------------------------------------
    # DOCUMENTS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            file_path TEXT,
            owner_id INTEGER
        )
    """)

    cursor.execute(
        "PRAGMA table_info(documents)"
    )

    document_columns = [
        column[1]
        for column in cursor.fetchall()
    ]

    if "file_path" not in document_columns:

        cursor.execute("""
            ALTER TABLE documents
            ADD COLUMN file_path TEXT
        """)

    if "owner_id" not in document_columns:

        cursor.execute("""
            ALTER TABLE documents
            ADD COLUMN owner_id INTEGER
        """)

    # --------------------------------------------------------
    # ACCESS REQUESTS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            document TEXT NOT NULL,
            purpose TEXT NOT NULL,
            permission TEXT NOT NULL,
            duration TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    cursor.execute(
        "PRAGMA table_info(access_requests)"
    )

    access_columns = [
        column[1]
        for column in cursor.fetchall()
    ]

    if "approved_at" not in access_columns:

        cursor.execute("""
            ALTER TABLE access_requests
            ADD COLUMN approved_at TEXT
        """)

    if "expires_at" not in access_columns:

        cursor.execute("""
            ALTER TABLE access_requests
            ADD COLUMN expires_at TEXT
        """)

    if "owner_id" not in access_columns:

        cursor.execute("""
            ALTER TABLE access_requests
            ADD COLUMN owner_id INTEGER
        """)

    if "organization_id" not in access_columns:

        cursor.execute("""
            ALTER TABLE access_requests
            ADD COLUMN organization_id INTEGER
        """)

    if "document_id" not in access_columns:

        cursor.execute("""
            ALTER TABLE access_requests
            ADD COLUMN document_id INTEGER
        """)

    # --------------------------------------------------------
    # ACTIVITY LOGS
    # --------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            details TEXT NOT NULL
        )
    """)

    # Add user_id without destroying old activity records.

    cursor.execute(
        "PRAGMA table_info(activity_logs)"
    )

    activity_columns = [
        column[1]
        for column in cursor.fetchall()
    ]

    if "user_id" not in activity_columns:

        cursor.execute("""
            ALTER TABLE activity_logs
            ADD COLUMN user_id INTEGER
        """)

    conn.commit()
    conn.close()


# ============================================================
# FILE VALIDATION
# ============================================================

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# ============================================================
# ACTIVITY LOG
# ============================================================

def log_activity(action, details):

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    user_id = session.get("user_id")

    cursor.execute("""
        INSERT INTO activity_logs (
            action,
            details,
            user_id
        )
        VALUES (?, ?, ?)
    """, (
        action,
        details,
        user_id
    ))

    conn.commit()
    conn.close()


# ============================================================
# AUTOMATIC ACCESS EXPIRY
# ============================================================

def update_expired_access():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    now = datetime.now().isoformat()

    cursor.execute("""
        SELECT
            id,
            organization,
            document
        FROM access_requests
        WHERE status = 'Approved'
        AND expires_at IS NOT NULL
        AND expires_at <= ?
    """, (
        now,
    ))

    expired_requests = cursor.fetchall()

    for item in expired_requests:

        request_id = item[0]
        organization = item[1]
        document = item[2]

        cursor.execute("""
            UPDATE access_requests
            SET status = 'Expired'
            WHERE id = ?
            AND status = 'Approved'
        """, (
            request_id,
        ))

        cursor.execute("""
            INSERT INTO activity_logs (
                action,
                details,
                user_id
            )
            SELECT
                ?,
                ?,
                organization_id
            FROM access_requests
            WHERE id = ?
        """, (
            "Access Expired",
            (
                f"Access for {organization} to "
                f"{document} expired automatically"
            ),
            request_id
        ))

    conn.commit()
    conn.close()


# ============================================================
# REGISTER
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        role = request.form.get(
            "role",
            ""
        )

        if not username:

            return render_template(
                "register.html",
                error="Please enter a username."
            )

        if not password:

            return render_template(
                "register.html",
                error="Please enter a password."
            )

        if password != confirm_password:

            return render_template(
                "register.html",
                error="Passwords do not match."
            )

        if role not in [
            "owner",
            "organization"
        ]:

            return render_template(
                "register.html",
                error="Please select a valid account type."
            )

        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()

        existing_user = cursor.execute("""
            SELECT id
            FROM users
            WHERE username = ?
        """, (
            username,
        )).fetchone()

        if existing_user:

            conn.close()

            return render_template(
                "register.html",
                error=(
                    "Username already exists. "
                    "Please choose another one."
                )
            )

        hashed_password = generate_password_hash(
            password
        )

        cursor.execute("""
            INSERT INTO users (
                username,
                password,
                role
            )
            VALUES (?, ?, ?)
        """, (
            username,
            hashed_password,
            role
        ))

        conn.commit()
        conn.close()

        log_activity(
            "User Registered",
            f"New {role} account created: @{username}"
        )

        return redirect("/login")

    return render_template("register.html")


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            return render_template(
                "login.html",
                error="Please enter username and password."
            )

        conn = sqlite3.connect(DATABASE)

        conn.row_factory = sqlite3.Row

        user = conn.execute("""
            SELECT *
            FROM users
            WHERE username = ?
        """, (
            username,
        )).fetchone()

        conn.close()

        if user is None:

            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        if not check_password_hash(
            user["password"],
            password
        ):

            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]

        log_activity(
            "User Login",
            f"{user['role']} logged in: @{user['username']}"
        )

        return redirect("/")

    return render_template("login.html")


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    username = session.get("username")

    if username:

        log_activity(
            "User Logout",
            f"User logged out: @{username}"
        )

    session.clear()

    return redirect("/login")


# ============================================================
# DATA OWNER PROFILE
# ============================================================

@app.route("/profile/<username>")
def profile(username):

    if "user_id" not in session:

        return redirect("/login")

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            username,
            role
        FROM users
        WHERE username = ?
        AND role = 'owner'
    """, (
        username,
    ))

    owner = cursor.fetchone()

    if owner is None:

        conn.close()

        return "Data Owner not found.", 404

    cursor.execute("""
        SELECT
            id,
            name,
            type,
            file_path,
            owner_id
        FROM documents
        WHERE owner_id = ?
        ORDER BY id DESC
    """, (
        owner[0],
    ))

    documents = cursor.fetchall()

    conn.close()

    return render_template(
        "profile.html",
        owner=owner,
        documents=documents
    )


# ============================================================
# SEARCH DATA OWNERS
# ============================================================

@app.route(
    "/search-owners",
    methods=["GET", "POST"]
)
def search_owners():

    if "user_id" not in session:

        return redirect("/login")

    if session.get("role") != "organization":

        return (
            "Only organizations can search for Data Owners.",
            403
        )

    owners = []

    if request.method == "POST":

        search_username = request.form.get(
            "username",
            ""
        ).strip()

        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                username,
                role
            FROM users
            WHERE role = 'owner'
            AND username LIKE ?
            ORDER BY username
        """, (
            "%" + search_username + "%",
        ))

        owners = cursor.fetchall()

        conn.close()

    return render_template(
        "search_owners.html",
        owners=owners
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def home():

    if "user_id" not in session:

        return redirect("/login")

    update_expired_access()

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    user_id = session["user_id"]
    role = session["role"]

    # --------------------------------------------------------
    # DATA OWNER
    # --------------------------------------------------------

    if role == "owner":

        document_count = cursor.execute("""
            SELECT COUNT(*)
            FROM documents
            WHERE owner_id = ?
        """, (
            user_id,
        )).fetchone()[0]

        pending_count = cursor.execute("""
            SELECT COUNT(*)
            FROM access_requests
            WHERE owner_id = ?
            AND status = 'Pending'
        """, (
            user_id,
        )).fetchone()[0]

        approved_count = cursor.execute("""
            SELECT COUNT(*)
            FROM access_requests
            WHERE owner_id = ?
            AND status = 'Approved'
        """, (
            user_id,
        )).fetchone()[0]

    # --------------------------------------------------------
    # ORGANIZATION
    # --------------------------------------------------------

    elif role == "organization":

        document_count = cursor.execute("""
            SELECT COUNT(*)
            FROM access_requests
            WHERE organization_id = ?
            AND status = 'Approved'
        """, (
            user_id,
        )).fetchone()[0]

        pending_count = cursor.execute("""
            SELECT COUNT(*)
            FROM access_requests
            WHERE organization_id = ?
            AND status = 'Pending'
        """, (
            user_id,
        )).fetchone()[0]

        approved_count = cursor.execute("""
            SELECT COUNT(*)
            FROM access_requests
            WHERE organization_id = ?
            AND status = 'Approved'
        """, (
            user_id,
        )).fetchone()[0]

    else:

        document_count = 0
        pending_count = 0
        approved_count = 0

    # --------------------------------------------------------
    # USER ACTIVITY COUNT
    # --------------------------------------------------------

    activity_count = cursor.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE user_id = ?
    """, (
        user_id,
    )).fetchone()[0]

    rejected_count = cursor.execute("""
        SELECT COUNT(*)
        FROM access_requests
        WHERE status = 'Rejected'
        AND (
            owner_id = ?
            OR organization_id = ?
        )
    """, (
        user_id,
        user_id
    )).fetchone()[0]

    conn.close()

    return render_template(
        "home.html",
        document_count=document_count,
        pending_count=pending_count,
        approved_count=approved_count,
        rejected_count=rejected_count,
        activity_count=activity_count
    )


# ============================================================
# DATA VAULT
# ============================================================

@app.route(
    "/vault",
    methods=["GET", "POST"]
)
def vault():

    if "user_id" not in session:

        return redirect("/login")

    if session.get("role") != "owner":

        return (
            "Only Data Owners can manage the Data Vault.",
            403
        )

    if request.method == "POST":

        document_name = request.form.get(
            "document_name",
            ""
        ).strip()

        document_type = request.form.get(
            "document_type",
            ""
        ).strip()

        uploaded_file = request.files.get(
            "document_file"
        )

        if not document_name:

            return "Document name is required.", 400

        if not document_type:

            return "Document type is required.", 400

        if not uploaded_file:

            return "No file selected.", 400

        if uploaded_file.filename == "":

            return "No file selected.", 400

        if not allowed_file(
            uploaded_file.filename
        ):

            return (
                "Invalid file type. "
                "Allowed formats: PDF, JPG, JPEG, PNG and DOCX.",
                400
            )

        original_filename = secure_filename(
            uploaded_file.filename
        )

        extension = original_filename.rsplit(
            ".",
            1
        )[1].lower()

        unique_filename = (
            str(uuid.uuid4())
            + "."
            + extension
        )

        file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            unique_filename
        )

        uploaded_file.save(file_path)

        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO documents (
                name,
                type,
                file_path,
                owner_id
            )
            VALUES (?, ?, ?, ?)
        """, (
            document_name,
            document_type,
            unique_filename,
            session["user_id"]
        ))

        conn.commit()
        conn.close()

        log_activity(
            "Document Uploaded",
            (
                f"@{session['username']} uploaded "
                f"{document_name} ({document_type}) "
                f"to Data Vault"
            )
        )

        return redirect("/vault")

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            type,
            file_path,
            owner_id
        FROM documents
        WHERE owner_id = ?
        ORDER BY id DESC
    """, (
        session["user_id"],
    ))

    documents = cursor.fetchall()

    conn.close()

    return render_template(
        "vault.html",
        documents=documents
    )


# ============================================================
# SECURE DOCUMENT ACCESS
# ============================================================

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):

    if "user_id" not in session:

        return redirect("/login")

    update_expired_access()

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            name,
            owner_id,
            file_path
        FROM documents
        WHERE file_path = ?
    """, (
        filename,
    ))

    document = cursor.fetchone()

    if document is None:

        conn.close()

        return "Document not found.", 404

    document_id = document[0]
    document_name = document[1]
    owner_id = document[2]

    # --------------------------------------------------------
    # DATA OWNER
    # --------------------------------------------------------

    if session.get("role") == "owner":

        if owner_id != session["user_id"]:

            conn.close()

            return "Access denied.", 403

        conn.close()

        return send_from_directory(
            app.config["UPLOAD_FOLDER"],
            filename
        )

    # --------------------------------------------------------
    # ORGANIZATION
    # --------------------------------------------------------

    if session.get("role") == "organization":

        cursor.execute("""
            SELECT
                id,
                permission,
                expires_at,
                status
            FROM access_requests
            WHERE organization_id = ?
            AND document_id = ?
            ORDER BY id DESC
            LIMIT 1
        """, (
            session["user_id"],
            document_id
        ))

        access_request = cursor.fetchone()

        if access_request is None:

            conn.close()

            return (
                "Access denied. "
                "No access request exists for this document.",
                403
            )

        request_id = access_request[0]
        permission = access_request[1]
        expires_at = access_request[2]
        status = access_request[3]

        if status != "Approved":

            conn.close()

            return (
                f"Access denied. "
                f"Current access status is {status}.",
                403
            )

        if not expires_at:

            conn.close()

            return (
                "Access denied. "
                "Access expiry is not defined.",
                403
            )

        try:

            expiry_time = datetime.fromisoformat(
                expires_at
            )

        except ValueError:

            conn.close()

            return (
                "Access denied. "
                "Invalid access expiry information.",
                403
            )

        if datetime.now() >= expiry_time:

            cursor.execute("""
                UPDATE access_requests
                SET status = 'Expired'
                WHERE id = ?
                AND status = 'Approved'
            """, (
                request_id,
            ))

            cursor.execute("""
                INSERT INTO activity_logs (
                    action,
                    details,
                    user_id
                )
                VALUES (?, ?, ?)
            """, (
                "Access Expired",
                (
                    f"Access expired for organization "
                    f"@{session['username']} on "
                    f"document '{document_name}'"
                ),
                session["user_id"]
            ))

            conn.commit()
            conn.close()

            return (
                "Access denied. This access has expired.",
                403
            )

        # ----------------------------------------------------
        # VIEW ONLY
        # ----------------------------------------------------

        if permission == "View Only":

            cursor.execute("""
                INSERT INTO activity_logs (
                    action,
                    details,
                    user_id
                )
                VALUES (?, ?, ?)
            """, (
                "Document Viewed",
                (
                    f"@{session['username']} viewed "
                    f"'{document_name}'"
                ),
                session["user_id"]
            ))

            conn.commit()
            conn.close()

            return send_from_directory(
                app.config["UPLOAD_FOLDER"],
                filename,
                as_attachment=False
            )

        # ----------------------------------------------------
        # DOWNLOAD
        # ----------------------------------------------------

        if permission == "Download":

            cursor.execute("""
                INSERT INTO activity_logs (
                    action,
                    details,
                    user_id
                )
                VALUES (?, ?, ?)
            """, (
                "Document Downloaded",
                (
                    f"@{session['username']} downloaded "
                    f"'{document_name}'"
                ),
                session["user_id"]
            ))

            conn.commit()
            conn.close()

            return send_from_directory(
                app.config["UPLOAD_FOLDER"],
                filename,
                as_attachment=True,
                download_name=document_name
            )

        conn.close()

        return "Access denied. Invalid permission.", 403

    conn.close()

    return "Access denied.", 403


# ============================================================
# ACCESS REQUESTS
# ============================================================

@app.route(
    "/access-requests",
    methods=["GET", "POST"]
)
def access_requests():

    if "user_id" not in session:

        return redirect("/login")

    update_expired_access()

    user_id = session["user_id"]
    role = session["role"]

    # ========================================================
    # ORGANIZATION
    # ========================================================

    if role == "organization":

        if request.method == "POST":

            owner_id = request.form.get(
                "owner_id"
            )

            document_id = request.form.get(
                "document_id"
            )

            purpose = request.form.get(
                "purpose",
                ""
            ).strip()

            permission = request.form.get(
                "permission"
            )

            duration = request.form.get(
                "duration"
            )

            if not owner_id or not document_id:

                return (
                    "Invalid Data Owner or document.",
                    400
                )

            if (
                not purpose
                or not permission
                or not duration
            ):

                return (
                    "Please fill all required fields.",
                    400
                )

            if permission not in [
                "View Only",
                "Download"
            ]:

                return "Invalid permission.", 400

            if duration not in [
                "24 Hours",
                "7 Days",
                "30 Days"
            ]:

                return "Invalid duration.", 400

            conn = sqlite3.connect(DATABASE)

            cursor = conn.cursor()

            cursor.execute("""
                SELECT
                    d.id,
                    d.name,
                    d.type,
                    d.owner_id,
                    u.username
                FROM documents d
                JOIN users u
                    ON d.owner_id = u.id
                WHERE d.id = ?
                AND d.owner_id = ?
                AND u.role = 'owner'
            """, (
                document_id,
                owner_id
            ))

            document_data = cursor.fetchone()

            if document_data is None:

                conn.close()

                return (
                    "Document or Data Owner not found.",
                    404
                )

            document_name = document_data[1]
            owner_username = document_data[4]

            organization_username = session["username"]

            # Prevent duplicate active/pending requests.

            existing = cursor.execute("""
                SELECT id
                FROM access_requests
                WHERE organization_id = ?
                AND document_id = ?
                AND status IN ('Pending', 'Approved')
            """, (
                user_id,
                document_id
            )).fetchone()

            if existing:

                conn.close()

                return (
                    "You already have a pending or active "
                    "request for this document.",
                    400
                )

            cursor.execute("""
                INSERT INTO access_requests (
                    organization,
                    document,
                    purpose,
                    permission,
                    duration,
                    status,
                    owner_id,
                    organization_id,
                    document_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                organization_username,
                document_name,
                purpose,
                permission,
                duration,
                "Pending",
                owner_id,
                user_id,
                document_id
            ))

            conn.commit()
            conn.close()

            log_activity(
                "Access Request Created",
                (
                    f"@{organization_username} requested "
                    f"{document_name} from "
                    f"@{owner_username} for {purpose}"
                )
            )

            return redirect(
                "/access-requests"
            )

        # ----------------------------------------------------
        # LOAD OWNERS
        # ----------------------------------------------------

        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                username,
                role
            FROM users
            WHERE role = 'owner'
            ORDER BY username
        """)

        owners = cursor.fetchall()

        # ----------------------------------------------------
        # LOAD DOCUMENTS
        # ----------------------------------------------------

        cursor.execute("""
            SELECT
                d.id,
                d.name,
                d.type,
                d.owner_id
            FROM documents d
            JOIN users u
                ON d.owner_id = u.id
            WHERE u.role = 'owner'
            ORDER BY d.id DESC
        """)

        documents = cursor.fetchall()

        # ----------------------------------------------------
        # LOAD ORGANIZATION REQUESTS
        # ----------------------------------------------------

        cursor.execute("""
            SELECT *
            FROM access_requests
            WHERE organization_id = ?
            ORDER BY id DESC
        """, (
            user_id,
        ))

        requests = cursor.fetchall()

        conn.close()

        selected_owner = request.args.get(
            "owner"
        )

        selected_document = request.args.get(
            "document"
        )

        return render_template(
            "access_requests.html",
            requests=requests,
            role=role,
            owners=owners,
            documents=documents,
            selected_owner=selected_owner,
            selected_document=selected_document
        )

    # ========================================================
    # DATA OWNER
    # ========================================================

    if role == "owner":

        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()

        cursor.execute("""
            SELECT *
            FROM access_requests
            WHERE owner_id = ?
            ORDER BY id DESC
        """, (
            user_id,
        ))

        requests = cursor.fetchall()

        conn.close()

        return render_template(
            "access_requests.html",
            requests=requests,
            role=role,
            owners=[],
            documents=[]
        )

    return "Invalid user role.", 403


# ============================================================
# APPROVE REQUEST
# ============================================================

@app.route(
    "/approve-request/<int:request_id>",
    methods=["POST"]
)
def approve_request(request_id):

    if "user_id" not in session:

        return redirect("/login")

    if session.get("role") != "owner":

        return (
            "Only Data Owners can approve requests.",
            403
        )

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            organization,
            document,
            duration,
            owner_id,
            status
        FROM access_requests
        WHERE id = ?
    """, (
        request_id,
    ))

    request_data = cursor.fetchone()

    if request_data is None:

        conn.close()

        return "Access request not found.", 404

    organization = request_data[0]
    document = request_data[1]
    duration = request_data[2]
    owner_id = request_data[3]
    status = request_data[4]

    if owner_id != session["user_id"]:

        conn.close()

        return (
            "You are not authorized to approve this request.",
            403
        )

    if status != "Pending":

        conn.close()

        return (
            "Only pending requests can be approved.",
            400
        )

    approved_at = datetime.now()

    if duration == "24 Hours":

        expires_at = approved_at + timedelta(
            hours=24
        )

    elif duration == "7 Days":

        expires_at = approved_at + timedelta(
            days=7
        )

    elif duration == "30 Days":

        expires_at = approved_at + timedelta(
            days=30
        )

    else:

        conn.close()

        return "Invalid duration.", 400

    cursor.execute("""
        UPDATE access_requests
        SET
            status = 'Approved',
            approved_at = ?,
            expires_at = ?
        WHERE id = ?
        AND status = 'Pending'
    """, (
        approved_at.isoformat(),
        expires_at.isoformat(),
        request_id
    ))

    conn.commit()
    conn.close()

    log_activity(
        "Access Approved",
        (
            f"{organization} approved for {document}. "
            f"Access expires on "
            f"{expires_at.strftime('%Y-%m-%d %H:%M')}"
        )
    )

    return redirect("/access-requests")


# ============================================================
# REJECT REQUEST
# ============================================================

@app.route(
    "/reject-request/<int:request_id>",
    methods=["POST"]
)
def reject_request(request_id):

    if "user_id" not in session:

        return redirect("/login")

    if session.get("role") != "owner":

        return (
            "Only Data Owners can reject requests.",
            403
        )

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            organization,
            document,
            owner_id,
            status
        FROM access_requests
        WHERE id = ?
    """, (
        request_id,
    ))

    request_data = cursor.fetchone()

    if request_data is None:

        conn.close()

        return "Access request not found.", 404

    organization = request_data[0]
    document = request_data[1]
    owner_id = request_data[2]
    status = request_data[3]

    if owner_id != session["user_id"]:

        conn.close()

        return (
            "You are not authorized to reject this request.",
            403
        )

    if status != "Pending":

        conn.close()

        return (
            "Only pending requests can be rejected.",
            400
        )

    cursor.execute("""
        UPDATE access_requests
        SET status = 'Rejected'
        WHERE id = ?
        AND status = 'Pending'
    """, (
        request_id,
    ))

    conn.commit()
    conn.close()

    log_activity(
        "Access Rejected",
        f"{organization} rejected for {document}"
    )

    return redirect("/access-requests")


# ============================================================
# REVOKE REQUEST
# ============================================================

@app.route(
    "/revoke-request/<int:request_id>",
    methods=["POST"]
)
def revoke_request(request_id):

    if "user_id" not in session:

        return redirect("/login")

    if session.get("role") != "owner":

        return (
            "Only Data Owners can revoke access.",
            403
        )

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            organization,
            document,
            owner_id,
            status
        FROM access_requests
        WHERE id = ?
    """, (
        request_id,
    ))

    request_data = cursor.fetchone()

    if request_data is None:

        conn.close()

        return "Access request not found.", 404

    organization = request_data[0]
    document = request_data[1]
    owner_id = request_data[2]
    status = request_data[3]

    if owner_id != session["user_id"]:

        conn.close()

        return (
            "You are not authorized to revoke this access.",
            403
        )

    if status != "Approved":

        conn.close()

        return (
            "Only active approved access can be revoked.",
            400
        )

    cursor.execute("""
        UPDATE access_requests
        SET status = 'Revoked'
        WHERE id = ?
        AND status = 'Approved'
    """, (
        request_id,
    ))

    conn.commit()
    conn.close()

    log_activity(
        "Access Revoked",
        (
            f"Access revoked from "
            f"{organization} for {document}"
        )
    )

    return redirect("/access-requests")


# ============================================================
# PRIVACY RISK ANALYSIS
# ============================================================

@app.route(
    "/risk-analysis",
    methods=["GET", "POST"]
)
def risk_analysis():

    if "user_id" not in session:

        return redirect("/login")

    risk = None
    score = 0
    recommendation = None

    if request.method == "POST":

        document_type = request.form.get(
            "document_type"
        )

        permission = request.form.get(
            "permission"
        )

        duration = request.form.get(
            "duration"
        )

        # ----------------------------------------------------
        # INPUT VALIDATION
        # ----------------------------------------------------

        if document_type not in [
            "Education",
            "Identity",
            "Financial",
            "Personal"
        ]:

            return (
                "Invalid document type.",
                400
            )

        if permission not in [
            "View Only",
            "Download"
        ]:

            return (
                "Invalid permission.",
                400
            )

        if duration not in [
            "24 Hours",
            "7 Days",
            "30 Days"
        ]:

            return (
                "Invalid duration.",
                400
            )

        # ----------------------------------------------------
        # MACHINE LEARNING FEATURES
        # ----------------------------------------------------

        if document_type in [
            "Identity",
            "Financial"
        ]:

            document_risk = 3

        elif document_type == "Personal":

            document_risk = 2

        else:

            document_risk = 1

        if permission == "Download":

            permission_risk = 3

        else:

            permission_risk = 1

        if duration == "30 Days":

            duration_risk = 3

        elif duration == "7 Days":

            duration_risk = 2

        else:

            duration_risk = 1

        features = [[
            document_risk,
            permission_risk,
            duration_risk
        ]]

        # ----------------------------------------------------
        # RANDOM FOREST PREDICTION
        # ----------------------------------------------------

        if risk_model is not None:

            try:

                risk = risk_model.predict(
                    features
                )[0]

            except Exception as exc:

                print(
                    f"AI model prediction error: {exc}"
                )

                risk = None

        # ----------------------------------------------------
        # EXPLAINABLE NUMERICAL SCORE
        # ----------------------------------------------------

        score = 0

        if document_type in [
            "Identity",
            "Financial"
        ]:

            score += 40

        elif document_type == "Personal":

            score += 30

        elif document_type == "Education":

            score += 20

        if permission == "Download":

            score += 30

        elif permission == "View Only":

            score += 10

        if duration == "30 Days":

            score += 30

        elif duration == "7 Days":

            score += 20

        elif duration == "24 Hours":

            score += 10

        # ----------------------------------------------------
        # FALLBACK CLASSIFICATION
        # ----------------------------------------------------

        if risk is None:

            if score >= 70:

                risk = "HIGH"

            elif score >= 40:

                risk = "MEDIUM"

            else:

                risk = "LOW"

        # ----------------------------------------------------
        # RECOMMENDATION
        # ----------------------------------------------------

        if risk == "HIGH":

            recommendation = (
                "AI detected a high privacy risk. "
                "Consider reducing permission or "
                "access duration."
            )

        elif risk == "MEDIUM":

            recommendation = (
                "AI detected a medium privacy risk. "
                "Review the request and grant only "
                "the minimum access required."
            )

        else:

            recommendation = (
                "AI detected a relatively low privacy risk. "
                "Normal privacy controls are recommended."
            )

    return render_template(
        "risk_analysis.html",
        risk=risk,
        score=score,
        recommendation=recommendation
    )


# ============================================================
# ACTIVITY HISTORY
# ============================================================

@app.route("/activity")
def activity():

    if "user_id" not in session:

        return redirect("/login")

    update_expired_access()

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            action,
            details
        FROM activity_logs
        WHERE user_id = ?
        ORDER BY id DESC
    """, (
        session["user_id"],
    ))

    activities = cursor.fetchall()

    conn.close()

    return render_template(
        "activity.html",
        activities=activities
    )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    init_db()

    app.run(
        debug=True
    )