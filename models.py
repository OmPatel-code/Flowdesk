import os
import re
import uuid
from collections import defaultdict
from threading import Lock
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from io import StringIO
import csv
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_, text
from sqlalchemy.orm import validates
import logging
import redis

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Rate limiting with Redis if available, fallback to in-memory
try:
    redis_client = redis.from_url(app.config['REDIS_URL'])
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        storage_uri=app.config['REDIS_URL'],
        default_limits=["100 per minute"]
    )
except:
    # Fallback to in-memory storage
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=["100 per minute"]
    )

# Security headers middleware
@app.after_request
def add_security_headers(response):
    for header, value in app.config['SECURITY_HEADERS'].items():
        response.headers[header] = value
    return response

# Setup logging
if not app.debug:
    logging.basicConfig(
        filename=app.config['LOG_FILE'],
        level=getattr(logging, app.config['LOG_LEVEL']),
        format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )

# Resolve upload folder path
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), app.config.get('UPLOAD_FOLDER', 'uploads'))
ALLOWED_EXTENSIONS = set(app.config.get('ALLOWED_EXTENSIONS', {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip'}))
ITEMS_PER_PAGE = app.config.get('ITEMS_PER_PAGE', 10)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

WORKFLOW_STATUSES = app.config.get('WORKFLOW_STATUSES', ['Created', 'In Progress', 'Completed', 'Cancelled'])
PRIORITY_LEVELS = app.config.get('PRIORITY_LEVELS', ['Low', 'Medium', 'High', 'Critical'])
WORKFLOW_CATEGORIES = app.config.get('WORKFLOW_CATEGORIES', ['General', 'Development', 'Marketing', 'Support', 'HR', 'Other'])

# ---------- Rate limiting (in-memory fallback) ----------
_login_attempts = defaultdict(list)
_rate_lock = Lock()
RATE_LIMIT_LOGIN = app.config.get('RATE_LIMIT_LOGIN_PER_MINUTE', 5)


def _rate_limit_login(ip):
    with _rate_lock:
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=1)
        _login_attempts[ip] = [t for t in _login_attempts[ip] if t > cutoff]
        if len(_login_attempts[ip]) >= RATE_LIMIT_LOGIN:
            return False
        _login_attempts[ip].append(now)
    return True


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------- Enhanced Password policy ----------
def validate_password(password):
    """Returns (True, None) if valid, else (False, error_message)."""
    min_len = app.config.get('PASSWORD_MIN_LENGTH', 8)
    if len(password) < min_len:
        return False, f'Password must be at least {min_len} characters'
    if app.config.get('PASSWORD_REQUIRE_LETTER', True) and not re.search(r'[a-zA-Z]', password):
        return False, 'Password must contain at least one letter'
    if app.config.get('PASSWORD_REQUIRE_DIGIT', True) and not re.search(r'\d', password):
        return False, 'Password must contain at least one number'
    if app.config.get('PASSWORD_REQUIRE_SPECIAL', False) and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, 'Password must contain at least one special character'
    if app.config.get('PASSWORD_REQUIRE_UPPERCASE', False) and not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'
    return True, None


# ---------- Enhanced Input validation ----------
def sanitize_str(value, max_length=0):
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if max_length and len(s) > max_length:
        s = s[:max_length]
    # Remove potentially dangerous characters
    s = re.sub(r'[<>"\']', '', s)
    return s


def validate_email(email):
    if not email or not email.strip():
        return True
    return bool(re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email.strip()))


def send_workflow_email(to_email, subject, body):
    """Send email if SMTP is configured."""
    if not app.config.get('MAIL_SERVER') or not to_email:
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = app.config.get('MAIL_DEFAULT_SENDER', 'noreply@localhost')
        msg['To'] = to_email
        msg.attach(MIMEText(body, 'plain'))
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config.get('MAIL_PORT', 587)) as s:
            if app.config.get('MAIL_USE_TLS'):
                s.starttls()
            if app.config.get('MAIL_USERNAME'):
                s.login(app.config['MAIL_USERNAME'], app.config.get('MAIL_PASSWORD', ''))
            s.send_message(msg)
        return True
    except Exception as e:
        app.logger.error(f"Email sending failed: {e}")
        return False


def _create_due_soon_notifications(user_id, workflows_due_soon):
    """Create notifications for workflows due soon (once per workflow per day)."""
    today = datetime.utcnow().date()
    for w in workflows_due_soon:
        recent = Notification.query.filter_by(user_id=user_id, link=f'/workflow/{w.id}').order_by(Notification.created_at.desc()).first()
        if recent and recent.created_at.date() == today:
            continue
        n = Notification(
            user_id=user_id,
            message=f'Workflow "{w.title}" is due soon ({w.due_date.strftime("%Y-%m-%d")})',
            link=f'/workflow/{w.id}'
        )
        db.session.add(n)

# ==================== ENHANCED MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(254), nullable=True, index=True)
    role = db.Column(db.String(20), nullable=False, default='User')
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    workflows = db.relationship('Workflow', backref='creator', lazy=True, cascade='all, delete-orphan')
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True, cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade='all, delete-orphan')
    workflow_comments = db.relationship('WorkflowComment', backref='author', lazy=True, cascade='all, delete-orphan')
    password_history = db.relationship('PasswordHistory', backref='user', lazy=True, cascade='all, delete-orphan')
    
    @validates('username')
    def validate_username(self, key, username):
        if not username or len(username.strip()) < 3:
            raise ValueError('Username must be at least 3 characters long')
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return username.strip()
    
    @validates('email')
    def validate_email(self, key, email):
        if email and not validate_email(email):
            raise ValueError('Invalid email format')
        return email
    
    def set_password(self, password):
        # Check password history
        if self.password_history:
            for hist in self.password_history[-app.config.get('PASSWORD_HISTORY_COUNT', 5):]:
                if check_password_hash(hist.password_hash, password):
                    raise ValueError('Cannot reuse recent passwords')
        
        self.password_hash = generate_password_hash(password)
        # Add to history
        hist = PasswordHistory(user_id=self.id, password_hash=self.password_hash)
        db.session.add(hist)
        db.session.commit()
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'Admin'
    
    def is_account_locked(self):
        return self.locked_until is not None and datetime.utcnow() < self.locked_until
    
    def check_and_lock_account(self):
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
    
    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        db.session.commit()

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class WorkflowTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    default_priority = db.Column(db.String(20), nullable=False, default='Medium')
    default_category = db.Column(db.String(50), nullable=True)
    default_due_days = db.Column(db.Integer, default=7)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class Workflow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=True, index=True)
    status = db.Column(db.String(50), nullable=False, default='Created', index=True)
    priority = db.Column(db.String(20), nullable=False, default='Medium', index=True)
    due_date = db.Column(db.DateTime, nullable=True, index=True)
    attachment = db.Column(db.String(255), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False, index=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    activity_logs = db.relationship('ActivityLog', backref='workflow', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('WorkflowComment', backref='workflow', lazy=True, cascade='all, delete-orphan')
    
    @validates('title')
    def validate_title(self, key, title):
        if not title or len(title.strip()) < 2:
            raise ValueError('Title must be at least 2 characters long')
        return title.strip()[:200]
    
    @validates('priority')
    def validate_priority(self, key, priority):
        if priority not in PRIORITY_LEVELS:
            raise ValueError(f'Invalid priority. Must be one of: {", ".join(PRIORITY_LEVELS)}')
        return priority
    
    @validates('status')
    def validate_status(self, key, status):
        if status not in WORKFLOW_STATUSES:
            raise ValueError(f'Invalid status. Must be one of: {", ".join(WORKFLOW_STATUSES)}')
        return status
    
    def is_overdue(self):  # NEW!
        """Check if workflow is overdue"""
        if self.due_date and self.status not in ['Completed', 'Cancelled'] and not self.is_deleted:
            return datetime.utcnow() > self.due_date
        return False

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workflow_id = db.Column(db.Integer, db.ForeignKey('workflow.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    old_status = db.Column(db.String(50), nullable=True)
    new_status = db.Column(db.String(50), nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    message = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(200), nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

class WorkflowComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workflow_id = db.Column(db.Integer, db.ForeignKey('workflow.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    @validates('body')
    def validate_body(self, key, body):
        if not body or len(body.strip()) < 1:
            raise ValueError('Comment cannot be empty')
        return body.strip()[:2000]

# ==================== HELPERS ====================

def is_logged_in():
    return 'user_id' in session

def get_current_user():
    if is_logged_in():
        return User.query.get(session['user_id'])
    return None

def require_login(f):
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        user = get_current_user()
        if user and user.is_account_locked():
            flash('Account temporarily locked due to multiple failed login attempts. Try again later.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def require_admin(f):
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        user = get_current_user()
        if not user.is_admin():
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# ==================== ROUTES ====================

@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        ip = request.remote_addr or '127.0.0.1'
        if not _rate_limit_login(ip):
            flash('Too many login attempts. Try again in a minute.', 'danger')
            return render_template('login.html')
        username = sanitize_str(request.form.get('username'), app.config.get('USERNAME_MAX_LENGTH', 50))
        password = request.form.get('password') or ''
        if not username:
            flash('Username is required', 'danger')
            return render_template('login.html')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not getattr(user, 'is_active', True):
                flash('Your account has been deactivated. Contact an admin.', 'danger')
                return render_template('login.html')
            if user.is_account_locked():
                flash('Account is temporarily locked. Try again later.', 'danger')
                return render_template('login.html')
            user.reset_failed_attempts()
            user.last_login = datetime.utcnow()
            db.session.commit()
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            if user:
                user.check_and_lock_account()
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/profile', methods=['GET', 'POST'])
@require_login
def profile():
    user = get_current_user()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'password':
            current = request.form.get('current_password', '')
            new_pass = request.form.get('new_password', '')
            if not user.check_password(current):
                flash('Current password is incorrect', 'danger')
            else:
                ok, err = validate_password(new_pass)
                if not ok:
                    flash(err, 'danger')
                else:
                    try:
                        user.set_password(new_pass)
                        flash('Password updated successfully', 'success')
                    except ValueError as e:
                        flash(str(e), 'danger')
        elif action == 'email':
            raw = request.form.get('email', '')
            email = sanitize_str(raw, app.config.get('EMAIL_MAX_LENGTH', 254)) or None
            if email and not validate_email(email):
                flash('Invalid email format', 'danger')
            else:
                user.email = email
                db.session.commit()
                flash('Email updated successfully', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@require_login
def dashboard():
    user = get_current_user()
    
    if user.is_admin():
        recent_workflows = Workflow.query.filter_by(is_deleted=False).order_by(Workflow.updated_at.desc()).limit(5).all()
        total_workflows = Workflow.query.filter_by(is_deleted=False).count()
        # NEW: Count overdue workflows
        overdue_count = Workflow.query.filter(
            Workflow.due_date < datetime.utcnow(),
            Workflow.status.notin_(['Completed', 'Cancelled']),
            Workflow.is_deleted == False
        ).count()
    else:
        recent_workflows = Workflow.query.filter_by(created_by=user.id, is_deleted=False).order_by(Workflow.updated_at.desc()).limit(5).all()
        total_workflows = Workflow.query.filter_by(created_by=user.id, is_deleted=False).count()
        # NEW: Count overdue workflows for user
        overdue_count = Workflow.query.filter(
            Workflow.created_by == user.id,
            Workflow.due_date < datetime.utcnow(),
            Workflow.status.notin_(['Completed', 'Cancelled']),
            Workflow.is_deleted == False
        ).count()
    
    due_soon_days = app.config.get('DUE_SOON_DAYS', 3)
    now = datetime.utcnow()
    soon_end = now + timedelta(days=due_soon_days)
    if user.is_admin():
        due_soon_workflows = Workflow.query.filter(
            Workflow.due_date != None,
            Workflow.due_date >= now,
            Workflow.due_date <= soon_end,
            Workflow.status.notin_(['Completed', 'Cancelled']),
            Workflow.is_deleted == False
        ).all()
    else:
        due_soon_workflows = Workflow.query.filter(
            Workflow.created_by == user.id,
            Workflow.due_date != None,
            Workflow.due_date >= now,
            Workflow.due_date <= soon_end,
            Workflow.status.notin_(['Completed', 'Cancelled']),
            Workflow.is_deleted == False
        ).all()
    try:
        _create_due_soon_notifications(user.id, due_soon_workflows)
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    return render_template('dashboard.html', 
                         user=user, 
                         recent_workflows=recent_workflows, 
                         total_workflows=total_workflows,
                         overdue_count=overdue_count,
                         due_soon_workflows=due_soon_workflows)

@app.route('/workflows')
@require_login
def workflows():
    user = get_current_user()
    status_filter = request.args.get('status')
    priority_filter = request.args.get('priority')
    category_filter = request.args.get('category')
    view_filter = request.args.get('view')
    search_q = sanitize_str(request.args.get('q', ''), 100) or ''
    page = request.args.get('page', 1, type=int)
    if page < 1:
        page = 1
    
    if user.is_admin():
        query = Workflow.query.filter_by(is_deleted=False)
    else:
        query = Workflow.query.filter_by(created_by=user.id, is_deleted=False)
    
    if search_q:
        search = f'%{search_q}%'
        query = query.filter(or_(
            Workflow.title.ilike(search),
            Workflow.description.ilike(search)
        ))
    
    if category_filter:
        query = query.filter_by(category=category_filter)
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    if priority_filter:
        query = query.filter_by(priority=priority_filter)
    
    if view_filter == 'overdue':
        query = query.filter(
            Workflow.due_date < datetime.utcnow(),
            Workflow.status.notin_(['Completed', 'Cancelled'])
        )
    
    pagination = query.order_by(Workflow.updated_at.desc()).paginate(
        page=page, per_page=ITEMS_PER_PAGE, error_out=False
    )
    
    return render_template('workflows.html', 
                         workflows=pagination.items, 
                         pagination=pagination,
                         statuses=WORKFLOW_STATUSES,
                         priorities=PRIORITY_LEVELS,
                         categories=WORKFLOW_CATEGORIES,
                         current_status=status_filter,
                         current_priority=priority_filter,
                         current_category=category_filter,
                         view_filter=view_filter,
                         search_q=search_q)

@app.route('/workflow/create', methods=['GET', 'POST'])
@require_login
@limiter.limit("20 per minute")
def create_workflow():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        priority = request.form.get('priority', 'Medium')
        due_date_str = request.form.get('due_date')
        template_id = request.form.get('template_id')
        
        category = sanitize_str(request.form.get('category'), 50) or None
        if category and category not in WORKFLOW_CATEGORIES:
            category = None
        if not title:
            flash('Title is required', 'danger')
            return render_template('create_workflow.html', priorities=PRIORITY_LEVELS, categories=WORKFLOW_CATEGORIES)
        due_date = None
        if due_date_str:
            try:
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
            except:
                flash('Invalid date format', 'warning')
        attachment_path = None
        if 'attachment' in request.files:
            f = request.files['attachment']
            if f and f.filename and allowed_file(f.filename):
                ext = f.filename.rsplit('.', 1)[1].lower()
                filename = f'{uuid.uuid4().hex}.{ext}'
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                attachment_path = filename
        
        user = get_current_user()
        workflow = Workflow(
            title=title, 
            description=description, 
            category=category,
            status='Created',
            priority=priority,
            due_date=due_date,
            attachment=attachment_path,
            created_by=user.id
        )
        db.session.add(workflow)
        db.session.flush()
        
        # NEW! Add due date to log details
        details = f'Priority: {priority}'
        if due_date:
            details += f', Due: {due_date.strftime("%Y-%m-%d")}'
        
        log = ActivityLog(
            workflow_id=workflow.id, 
            user_id=user.id, 
            action='created', 
            new_status='Created',
            details=details
        )
        db.session.add(log)
        n = Notification(user_id=user.id, message=f'Workflow "{title}" created', link=f'/workflow/{workflow.id}')
        db.session.add(n)
        db.session.commit()
        
        flash('Workflow created successfully', 'success')
        return redirect(url_for('workflow_detail', workflow_id=workflow.id))
    
    templates = WorkflowTemplate.query.filter_by(is_active=True).all() if get_current_user().is_admin() else []
    return render_template('create_workflow.html', priorities=PRIORITY_LEVELS, categories=WORKFLOW_CATEGORIES, templates=templates)

@app.route('/workflow/<int:workflow_id>')
@require_login
def workflow_detail(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    
    if not user.is_admin() and workflow.created_by != user.id:
        flash('You do not have permission to view this workflow', 'danger')
        return redirect(url_for('workflows'))
    
    logs = ActivityLog.query.filter_by(workflow_id=workflow_id).order_by(ActivityLog.timestamp.desc()).all()
    comments = WorkflowComment.query.filter_by(workflow_id=workflow_id).order_by(WorkflowComment.created_at.asc()).all()
    
    return render_template('workflow_detail.html', 
                         workflow=workflow, 
                         logs=logs, 
                         comments=comments,
                         statuses=WORKFLOW_STATUSES,
                         priorities=PRIORITY_LEVELS,
                         categories=WORKFLOW_CATEGORIES)

@app.route('/workflow/<int:workflow_id>/update', methods=['POST'])
@require_login
@limiter.limit("20 per minute")
def update_workflow(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    
    if not user.is_admin() and workflow.created_by != user.id:
        flash('You do not have permission to update this workflow', 'danger')
        return redirect(url_for('workflows'))
    
    old_status = workflow.status
    old_priority = workflow.priority
    old_due_date = workflow.due_date
    
    new_status = request.form.get('status')
    new_priority = request.form.get('priority')
    due_date_str = request.form.get('due_date')
    if new_status and new_status in WORKFLOW_STATUSES:
        workflow.status = new_status
    if new_priority and new_priority in PRIORITY_LEVELS:
        workflow.priority = new_priority
    
    # NEW! Update due date
    if due_date_str:
        try:
            workflow.due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
        except:
            flash('Invalid date format', 'warning')
    
    workflow.updated_at = datetime.utcnow()
    
    new_category = sanitize_str(request.form.get('category'), 50) or None
    if new_category and new_category in WORKFLOW_CATEGORIES:
        workflow.category = new_category
    
    if old_status != workflow.status:
        n = Notification(user_id=workflow.created_by, message=f'Workflow "{workflow.title}" status: {old_status} -> {workflow.status}', link=f'/workflow/{workflow.id}')
        db.session.add(n)
        creator = User.query.get(workflow.created_by)
        if creator and creator.email and app.config.get('MAIL_SERVER'):
            send_workflow_email(
                creator.email,
                f'Workflow status updated: {workflow.title}',
                f'Your workflow "{workflow.title}" has been updated from {old_status} to {workflow.status}.'
            )
        log = ActivityLog(
            workflow_id=workflow.id, 
            user_id=user.id, 
            action='status_changed', 
            old_status=old_status, 
            new_status=workflow.status
        )
        db.session.add(log)
    
    # Log priority change
    if old_priority != workflow.priority:
        log = ActivityLog(
            workflow_id=workflow.id,
            user_id=user.id,
            action='priority_changed',
            details=f'{old_priority} → {workflow.priority}'
        )
        db.session.add(log)
    
    # NEW! Log due date change
    if old_due_date != workflow.due_date:
        old_str = old_due_date.strftime('%Y-%m-%d') if old_due_date else 'None'
        new_str = workflow.due_date.strftime('%Y-%m-%d') if workflow.due_date else 'None'
        log = ActivityLog(
            workflow_id=workflow.id,
            user_id=user.id,
            action='due_date_changed',
            details=f'{old_str} → {new_str}'
        )
        db.session.add(log)
    
    if 'attachment' in request.files:
        f = request.files['attachment']
        if f and f.filename and allowed_file(f.filename):
            ext = f.filename.rsplit('.', 1)[1].lower()
            filename = f'{uuid.uuid4().hex}.{ext}'
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            workflow.attachment = filename
    
    db.session.commit()
    
    flash('Workflow updated successfully', 'success')
    return redirect(url_for('workflow_detail', workflow_id=workflow_id))

@app.route('/workflow/<int:workflow_id>/comment', methods=['POST'])
@require_login
@limiter.limit("30 per minute")
def add_workflow_comment(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    if not user.is_admin() and workflow.created_by != user.id:
        flash('You do not have permission to comment on this workflow', 'danger')
        return redirect(url_for('workflows'))
    body = sanitize_str(request.form.get('body', ''), 2000)
    if not body:
        flash('Comment cannot be empty', 'danger')
        return redirect(url_for('workflow_detail', workflow_id=workflow_id))
    c = WorkflowComment(workflow_id=workflow_id, user_id=user.id, body=body)
    db.session.add(c)
    db.session.commit()
    flash('Comment added', 'success')
    return redirect(url_for('workflow_detail', workflow_id=workflow_id))

@app.route('/workflow/<int:workflow_id>/delete', methods=['POST'])
@require_login
@limiter.limit("10 per minute")
def delete_workflow(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    
    if not user.is_admin() and workflow.created_by != user.id:
        flash('You do not have permission to delete this workflow', 'danger')
        return redirect(url_for('workflows'))
    
    workflow.is_deleted = True
    workflow.deleted_at = datetime.utcnow()
    workflow.deleted_by = user.id
    db.session.commit()
    flash('Workflow deleted successfully', 'success')
    return redirect(url_for('workflows'))

@app.route('/uploads/<filename>')
@require_login
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/analytics')
@require_login
def analytics():
    user = get_current_user()
    
    if user.is_admin():
        status_counts = db.session.query(Workflow.status, func.count(Workflow.id)).filter_by(is_deleted=False).group_by(Workflow.status).all()
        priority_counts = db.session.query(Workflow.priority, func.count(Workflow.id)).filter_by(is_deleted=False).group_by(Workflow.priority).all()
        total_workflows = Workflow.query.filter_by(is_deleted=False).count()
        total_users = User.query.count()
        total_activities = ActivityLog.query.count()
        recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
        logs_query = ActivityLog.query.order_by(ActivityLog.timestamp.desc())
        # NEW! Overdue count
        overdue_count = Workflow.query.filter(
            Workflow.due_date < datetime.utcnow(),
            Workflow.status.notin_(['Completed', 'Cancelled']),
            Workflow.is_deleted == False
        ).count()
    else:
        status_counts = db.session.query(Workflow.status, func.count(Workflow.id)).filter_by(created_by=user.id, is_deleted=False).group_by(Workflow.status).all()
        priority_counts = db.session.query(Workflow.priority, func.count(Workflow.id)).filter_by(created_by=user.id, is_deleted=False).group_by(Workflow.priority).all()
        total_workflows = Workflow.query.filter_by(created_by=user.id, is_deleted=False).count()
        total_users = 1
        total_activities = ActivityLog.query.filter_by(user_id=user.id).count()
        recent_logs = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.timestamp.desc()).limit(10).all()
        logs_query = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.timestamp.desc())
    
    page = request.args.get('page', 1, type=int)
    logs_pagination = logs_query.paginate(page=page, per_page=ITEMS_PER_PAGE, error_out=False)
    if not user.is_admin():
        overdue_count = Workflow.query.filter(
            Workflow.created_by == user.id,
            Workflow.due_date < datetime.utcnow(),
            Workflow.status.notin_(['Completed', 'Cancelled']),
            Workflow.is_deleted == False
        ).count()
    
    status_dict = {status: 0 for status in WORKFLOW_STATUSES}
    for status, count in status_counts:
        status_dict[status] = count
    
    priority_dict = {priority: 0 for priority in PRIORITY_LEVELS}
    for priority, count in priority_counts:
        priority_dict[priority] = count
    
    return render_template('analytics.html', 
                         status_dict=status_dict,
                         priority_dict=priority_dict,
                         total_workflows=total_workflows, 
                         total_users=total_users, 
                         total_activities=total_activities, 
                         recent_logs=recent_logs,
                         logs_pagination=logs_pagination,
                         overdue_count=overdue_count)

@app.route('/notifications')
@require_login
def notifications():
    user = get_current_user()
    notifs = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(50).all()
    return render_template('notifications.html', notifications=notifs)

@app.route('/workflows/export')
@require_login
def export_workflows():
    user = get_current_user()
    if user.is_admin():
        q = Workflow.query.filter_by(is_deleted=False).order_by(Workflow.updated_at.desc())
    else:
        q = Workflow.query.filter_by(created_by=user.id, is_deleted=False).order_by(Workflow.updated_at.desc())
    workflows = q.all()
    si = StringIO()
    w = csv.writer(si)
    w.writerow(['ID', 'Title', 'Description', 'Category', 'Status', 'Priority', 'Due Date', 'Created By', 'Created At', 'Updated At'])
    for wf in workflows:
        w.writerow([
            wf.id, wf.title, (wf.description or '')[:500], wf.category or '',
            wf.status, wf.priority,
            wf.due_date.strftime('%Y-%m-%d') if wf.due_date else '',
            wf.creator.username if wf.creator else '',
            wf.created_at.strftime('%Y-%m-%d %H:%M') if wf.created_at else '',
            wf.updated_at.strftime('%Y-%m-%d %H:%M') if wf.updated_at else ''
        ])
    from flask import Response
    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=workflows.csv'})

@app.route('/analytics/export')
@require_login
def export_analytics():
    user = get_current_user()
    si = StringIO()
    w = csv.writer(si)
    w.writerow(['Metric', 'Value'])
    if user.is_admin():
        w.writerow(['Total Workflows', Workflow.query.filter_by(is_deleted=False).count()])
        w.writerow(['Total Users', User.query.count()])
        w.writerow(['Total Activities', ActivityLog.query.count()])
        for status in WORKFLOW_STATUSES:
            c = Workflow.query.filter_by(status=status, is_deleted=False).count()
            w.writerow([f'Status: {status}', c])
        for pri in PRIORITY_LEVELS:
            c = Workflow.query.filter_by(priority=pri, is_deleted=False).count()
            w.writerow([f'Priority: {pri}', c])
    else:
        w.writerow(['My Workflows', Workflow.query.filter_by(created_by=user.id, is_deleted=False).count()])
        w.writerow(['My Activities', ActivityLog.query.filter_by(user_id=user.id).count()])
        for status in WORKFLOW_STATUSES:
            c = Workflow.query.filter_by(created_by=user.id, status=status, is_deleted=False).count()
            w.writerow([f'Status: {status}', c])
    from flask import Response
    return Response(si.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=analytics.csv'})

# ==================== REST API ====================
API_PREFIX = app.config.get('API_PREFIX', '/api/v1')

def _api_workflow_to_dict(wf):
    return {
        'id': wf.id, 'title': wf.title, 'description': wf.description or '',
        'category': wf.category or '', 'status': wf.status, 'priority': wf.priority,
        'due_date': wf.due_date.isoformat() if wf.due_date else None,
        'created_by': wf.created_by, 'created_at': wf.created_at.isoformat() if wf.created_at else None,
        'updated_at': wf.updated_at.isoformat() if wf.updated_at else None,
    }

@app.route(f'{API_PREFIX}/workflows', methods=['GET'])
@require_login
@limiter.limit("60 per minute")
def api_list_workflows():
    user = get_current_user()
    if user.is_admin():
        q = Workflow.query.filter_by(is_deleted=False).order_by(Workflow.updated_at.desc())
    else:
        q = Workflow.query.filter_by(created_by=user.id, is_deleted=False).order_by(Workflow.updated_at.desc())
    status = request.args.get('status')
    if status and status in WORKFLOW_STATUSES:
        q = q.filter_by(status=status)
    limit = min(request.args.get('limit', 50, type=int), 100)
    workflows = q.limit(limit).all()
    return jsonify({'workflows': [_api_workflow_to_dict(w) for w in workflows]})

@app.route(f'{API_PREFIX}/workflows/<int:workflow_id>', methods=['GET'])
@require_login
@limiter.limit("60 per minute")
def api_get_workflow(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    if not user.is_admin() and workflow.created_by != user.id:
        return jsonify({'error': 'Forbidden'}), 403
    return jsonify(_api_workflow_to_dict(workflow))

@app.route(f'{API_PREFIX}/workflows', methods=['POST'])
@require_login
@limiter.limit("20 per minute")
def api_create_workflow():
    data = request.get_json() or {}
    title = sanitize_str(data.get('title'), app.config.get('TITLE_MAX_LENGTH', 200))
    if not title:
        return jsonify({'error': 'title is required'}), 400
    user = get_current_user()
    priority = data.get('priority', 'Medium')
    if priority not in PRIORITY_LEVELS:
        priority = 'Medium'
    category = sanitize_str(data.get('category'), 50)
    if category and category not in WORKFLOW_CATEGORIES:
        category = None
    due_date = None
    if data.get('due_date'):
        try:
            due_date = datetime.fromisoformat(data['due_date'].replace('Z', '+00:00'))
        except Exception:
            pass
    wf = Workflow(title=title, description=sanitize_str(data.get('description'), 5000) or None,
                  category=category, status='Created', priority=priority, due_date=due_date, created_by=user.id)
    db.session.add(wf)
    db.session.commit()
    return jsonify(_api_workflow_to_dict(wf)), 201

@app.route(f'{API_PREFIX}/workflows/<int:workflow_id>', methods=['PUT'])
@require_login
@limiter.limit("20 per minute")
def api_update_workflow(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    if not user.is_admin() and workflow.created_by != user.id:
        return jsonify({'error': 'Forbidden'}), 403
    data = request.get_json() or {}
    if data.get('title'):
        workflow.title = sanitize_str(data['title'], app.config.get('TITLE_MAX_LENGTH', 200)) or workflow.title
    if data.get('description') is not None:
        workflow.description = sanitize_str(data.get('description'), 5000)
    if data.get('status') in WORKFLOW_STATUSES:
        workflow.status = data['status']
    if data.get('priority') in PRIORITY_LEVELS:
        workflow.priority = data['priority']
    if data.get('category') is not None:
        c = sanitize_str(data.get('category'), 50)
        workflow.category = c if c in WORKFLOW_CATEGORIES else workflow.category
    if data.get('due_date') is not None:
        try:
            workflow.due_date = datetime.fromisoformat(str(data['due_date']).replace('Z', '+00:00')) if data.get('due_date') else None
        except Exception:
            pass
    workflow.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify(_api_workflow_to_dict(workflow))

@app.route(f'{API_PREFIX}/workflows/<int:workflow_id>', methods=['DELETE'])
@require_login
@limiter.limit("10 per minute")
def api_delete_workflow(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    if not user.is_admin() and workflow.created_by != user.id:
        return jsonify({'error': 'Forbidden'}), 403
    workflow.is_deleted = True
    workflow.deleted_at = datetime.utcnow()
    workflow.deleted_by = user.id
    db.session.commit()
    return '', 204

# ==================== USER MANAGEMENT (Admin only) ====================

USER_ROLES = ['Admin', 'User']

@app.route('/users')
@require_login
@require_admin
def users():
    users_list = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users_list)

@app.route('/user/create', methods=['GET', 'POST'])
@require_login
@require_admin
@limiter.limit("10 per minute")
def create_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip() or None
        role = request.form.get('role', 'User')
        
        username = sanitize_str(username, app.config.get('USERNAME_MAX_LENGTH', 50))
        email = sanitize_str(email, app.config.get('EMAIL_MAX_LENGTH', 254)) or None
        if not username:
            flash('Username is required', 'danger')
            return render_template('create_user.html', roles=USER_ROLES)
        ok, err = validate_password(password)
        if not ok:
            flash(err, 'danger')
            return render_template('create_user.html', roles=USER_ROLES)
        if email and not validate_email(email):
            flash('Invalid email format', 'danger')
            return render_template('create_user.html', roles=USER_ROLES)
        if User.query.filter_by(username=username).first():
            flash(f'Username "{username}" already exists', 'danger')
            return render_template('create_user.html', roles=USER_ROLES)
        if role not in USER_ROLES:
            role = 'User'
        
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash(f'User "{username}" created successfully', 'success')
        return redirect(url_for('users'))
    
    return render_template('create_user.html', roles=USER_ROLES)

@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@require_login
@require_admin
@limiter.limit("10 per minute")
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip() or None
        role = request.form.get('role', user.role)
        password = request.form.get('password', '')
        
        if not username:
            flash('Username is required', 'danger')
            return render_template('edit_user.html', user=user, roles=USER_ROLES)
        if User.query.filter(User.username == username, User.id != user.id).first():
            flash(f'Username "{username}" already taken', 'danger')
            return render_template('edit_user.html', user=user, roles=USER_ROLES)
        if role not in USER_ROLES:
            role = user.role
        
        user.username = username
        user.email = email
        user.role = role
        if password:
            ok, err = validate_password(password)
            if not ok:
                flash(err, 'danger')
                return render_template('edit_user.html', user=user, roles=USER_ROLES)
            user.set_password(password)
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('users'))
    
    return render_template('edit_user.html', user=user, roles=USER_ROLES)

@app.route('/user/<int:user_id>/toggle', methods=['POST'])
@require_login
@require_admin
@limiter.limit("10 per minute")
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    current = get_current_user()
    
    if user.id == current.id:
        flash('You cannot deactivate your own account', 'danger')
        return redirect(url_for('users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User "{user.username}" {status}', 'success')
    return redirect(url_for('users'))

# ==================== INIT ====================

def migrate_db():
    """Add new columns/tables for existing databases."""
    from sqlalchemy import text
    tbl_user = User.__table__.name
    tbl_workflow = Workflow.__table__.name
    migrations = [
        (f'ALTER TABLE "{tbl_user}" ADD COLUMN email VARCHAR(254)', 'user'),
        (f'ALTER TABLE "{tbl_user}" ADD COLUMN is_active INTEGER DEFAULT 1', 'user'),
        (f'ALTER TABLE "{tbl_user}" ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP', 'user'),
        (f'ALTER TABLE "{tbl_user}" ADD COLUMN last_login DATETIME', 'user'),
        (f'ALTER TABLE "{tbl_user}" ADD COLUMN failed_login_attempts INTEGER DEFAULT 0', 'user'),
        (f'ALTER TABLE "{tbl_user}" ADD COLUMN locked_until DATETIME', 'user'),
        (f'ALTER TABLE "{tbl_workflow}" ADD COLUMN attachment VARCHAR(255)', 'workflow'),
        (f'ALTER TABLE "{tbl_workflow}" ADD COLUMN category VARCHAR(50)', 'workflow'),
        (f'ALTER TABLE "{tbl_workflow}" ADD COLUMN is_deleted INTEGER DEFAULT 0', 'workflow'),
        (f'ALTER TABLE "{tbl_workflow}" ADD COLUMN deleted_at DATETIME', 'workflow'),
        (f'ALTER TABLE "{tbl_workflow}" ADD COLUMN deleted_by INTEGER', 'workflow'),
    ]
    for col_sql, _ in migrations:
        try:
            db.session.execute(text(col_sql))
            db.session.commit()
        except Exception:
            db.session.rollback()
            db.drop_all()
            db.create_all()
            return

def init_db():
    with app.app_context():
        db.create_all()
        migrate_db()
        if User.query.first() is None:
            admin = User(username='admin', role='Admin')
            admin.set_password('admin123')
            db.session.add(admin)
            
            user = User(username='user', role='User')
            user.set_password('user123')
            db.session.add(user)
            
            db.session.commit()
            print("\n" + "="*50)
            print("[OK] DATABASE READY!")
            print("="*50)
            print("  Admin: username=admin, password=admin123")
            print("  User:  username=user,  password=user123")
            print("="*50 + "\n")

if __name__ == '__main__':
    init_db()
    print("Server starting at http://127.0.0.1:5000")
    app.run(debug=True)