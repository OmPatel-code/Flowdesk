import os
import re
import uuid
import json
import functools
from collections import defaultdict
from threading import Lock
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from io import StringIO
import csv
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_, text
from flask_mail import Mail, Message
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

app = Flask(__name__)
app.config.from_object('config.Config')
# Resolve upload folder path
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), app.config.get('UPLOAD_FOLDER', 'uploads'))
ALLOWED_EXTENSIONS = set(app.config.get('ALLOWED_EXTENSIONS', {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip'}))
ITEMS_PER_PAGE = app.config.get('ITEMS_PER_PAGE', 10)

db = SQLAlchemy(app)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

WORKFLOW_STATUSES = app.config.get('WORKFLOW_STATUSES', ['Created', 'In Progress', 'Completed', 'Cancelled'])
PRIORITY_LEVELS = app.config.get('PRIORITY_LEVELS', ['Low', 'Medium', 'High', 'Critical'])
WORKFLOW_CATEGORIES = app.config.get('WORKFLOW_CATEGORIES', ['General', 'Development', 'Marketing', 'Support', 'HR', 'Other'])

# ---------- Rate limiting (in-memory) ----------
_login_attempts = defaultdict(list)
_rate_lock = Lock()
RATE_LIMIT_LOGIN = app.config.get('RATE_LIMIT_LOGIN_PER_MINUTE', 5)


def _rate_limit_login(ip):
    with _rate_lock:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=1)
        _login_attempts[ip] = [t for t in _login_attempts[ip] if t > cutoff]
        if len(_login_attempts[ip]) >= RATE_LIMIT_LOGIN:
            return False
        _login_attempts[ip].append(now)
    return True


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------- Password policy ----------
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
        return False, 'Password must contain at least one special character (!@#$%^&* etc.)'
    if app.config.get('PASSWORD_REQUIRE_UPPERCASE', False) and not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'
    return True, None


# ---------- Input validation ----------
def sanitize_str(value, max_length=0):
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    if max_length and len(s) > max_length:
        s = s[:max_length]
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


def send_deadline_reminders():
    """Send deadline reminder emails (2 days, 1 day before, and on due date)"""
    today = datetime.now(timezone.utc).date()
    tomorrow = today + timedelta(days=1)
    two_days = today + timedelta(days=2)
    
    # Get workflows due soon
    workflows_due = Workflow.query.filter(
        Workflow.due_date.isnot(None),
        Workflow.status.notin_(['Completed', 'Cancelled']),
        db.or_(
            Workflow.due_date == tomorrow,  # 1 day before
            Workflow.due_date == two_days,  # 2 days before
            Workflow.due_date == today      # Due today
        )
    ).all()
    
    for workflow in workflows_due:
        # Calculate days until due
        days_until = (workflow.due_date.date() - today).days
        
        # Determine reminder type
        if days_until == 2:
            reminder_text = "in 2 days"
        elif days_until == 1:
            reminder_text = "tomorrow"
        else:
            reminder_text = "TODAY"
        
        # Send email to creator
        if workflow.creator and workflow.creator.email:
            subject = f"⏰ Deadline Reminder: '{workflow.title}' due {reminder_text}"
            body = f"""
Hello {workflow.creator.username},

This is a reminder that your workflow is due {reminder_text}.

Workflow: {workflow.title}
Due Date: {workflow.due_date.strftime('%Y-%m-%d %H:%M')}
Priority: {workflow.priority}
Status: {workflow.status}

Please complete this workflow on time.

Best regards,
Workflow Platform
            """
            send_workflow_email(workflow.creator.email, subject, body)
        
        # Send email to assignee if different
        if workflow.assigned_to and workflow.assignee != workflow.creator and workflow.assignee.email:
            subject = f"⏰ Deadline Reminder: '{workflow.title}' due {reminder_text}"
            body = f"""
Hello {workflow.assignee.username},

This is a reminder that the workflow assigned to you is due {reminder_text}.

Workflow: {workflow.title}
Assigned by: {workflow.creator.username if workflow.creator else 'Unknown'}
Due Date: {workflow.due_date.strftime('%Y-%m-%d %H:%M')}
Priority: {workflow.priority}
Status: {workflow.status}

Please complete this workflow on time.

Best regards,
Workflow Platform
            """
            send_workflow_email(workflow.assignee.email, subject, body)


def send_monthly_analytics():
    """Send monthly analytics emails to all users and admin summary"""
    today = datetime.now(timezone.utc).date()
    first_day = today.replace(day=1)
    
    # Get all active users
    users = User.query.filter_by(is_active=True).all()
    
    for user in users:
        # Get user's workflow stats
        total_workflows = Workflow.query.filter_by(created_by=user.id).count()
        completed_workflows = Workflow.query.filter_by(created_by=user.id, status='Completed').count()
        
        # Get workflows created this month
        monthly_workflows = Workflow.query.filter(
            Workflow.created_by == user.id,
            Workflow.created_at >= first_day
        ).count()
        
        # Get overdue tasks
        overdue_count = Workflow.query.filter(
            Workflow.created_by == user.id,
            Workflow.due_date < datetime.now(timezone.utc),
            Workflow.status.notin_(['Completed', 'Cancelled'])
        ).count()
        
        subject = f"📊 Monthly Analytics Report - {today.strftime('%B %Y')}"
        body = f"""
Hello {user.username},

Here's your monthly workflow analytics for {today.strftime('%B %Y')}:

📈 Your Statistics:
• Total Workflows: {total_workflows}
• Completed Workflows: {completed_workflows}
• Completion Rate: {int((completed_workflows/total_workflows)*100) if total_workflows > 0 else 0}%
• Workflows Created This Month: {monthly_workflows}
• Overdue Tasks: {overdue_count}

🎯 Recommendations:
{f"You have {overdue_count} overdue tasks. Please review and update them." if overdue_count > 0 else "Great job keeping up with your deadlines!"}

Keep up the great work!

Best regards,
Workflow Platform
        """
        
        send_workflow_email(user.email, subject, body)
    
    # Send admin summary
    admin_users = User.query.filter_by(role='Admin', is_active=True).all()
    total_system_workflows = Workflow.query.count()
    total_completed = Workflow.query.filter_by(status='Completed').count()
    total_users = User.query.filter_by(is_active=True).count()
    monthly_new_workflows = Workflow.query.filter(
        Workflow.created_at >= first_day
    ).count()
    
    admin_subject = f"🔧 Admin Monthly Analytics - {today.strftime('%B %Y')}"
    admin_body = f"""
Admin Monthly System Analytics for {today.strftime('%B %Y')}:

📊 System Overview:
• Total Workflows: {total_system_workflows}
• Completed Workflows: {total_completed}
• System Completion Rate: {int((total_completed/total_system_workflows)*100) if total_system_workflows > 0 else 0}%
• Active Users: {total_users}

👥 User Activity:
• Total Users: {total_users}
• Admin Users: {len(admin_users)}

📈 Platform Performance:
• Monthly Growth: {monthly_new_workflows} new workflows
• System Health: {'Excellent' if total_system_workflows > 0 else 'New System'}

Best regards,
Workflow Platform
    """
    
    for admin in admin_users:
        send_workflow_email(admin.email, admin_subject, admin_body)


def start_scheduler():
    """Start the email scheduler.
    APScheduler runs jobs in background threads with NO Flask app context.
    Every job must be wrapped in app.app_context() or queries will silently fail.
    """
    scheduler = BackgroundScheduler()

    def _deadline_job():
        with app.app_context():
            try:
                send_deadline_reminders()
            except Exception as e:
                app.logger.error(f"Deadline reminder job failed: {e}")

    def _analytics_job():
        with app.app_context():
            try:
                send_monthly_analytics()
            except Exception as e:
                app.logger.error(f"Monthly analytics job failed: {e}")

    scheduler.add_job(
        func=_deadline_job,
        trigger=CronTrigger(minute=0),
        id='deadline_reminders',
        name='Send deadline reminder emails',
        replace_existing=True
    )
    scheduler.add_job(
        func=_analytics_job,
        trigger=CronTrigger(day=1, hour=9, minute=0),
        id='monthly_analytics',
        name='Send monthly analytics emails',
        replace_existing=True
    )
    scheduler.start()
    return scheduler


def _create_due_soon_notifications(user_id, workflows_due_soon):
    """Create notifications for workflows due soon (once per workflow per day)."""
    today = datetime.now(timezone.utc).date()
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

# ==================== MODELS ====================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), nullable=True)
    role = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)

    workflows = db.relationship('Workflow', foreign_keys='Workflow.created_by', backref='creator', lazy=True)
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade='all, delete-orphan')
    workflow_comments = db.relationship('WorkflowComment', backref='author', lazy=True)
    assigned_workflows = db.relationship('Workflow', foreign_keys='Workflow.assigned_to', backref='assignee', lazy=True)
    automations = db.relationship('WorkflowAutomation', backref='creator', lazy=True)
    templates = db.relationship('WorkflowTemplate', backref='creator', lazy=True)
    password_history = db.relationship('PasswordHistory', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        if self.id:
            history_count = app.config.get('PASSWORD_HISTORY_COUNT', 5)
            recent = PasswordHistory.query.filter_by(user_id=self.id)\
                .order_by(PasswordHistory.created_at.desc()).limit(history_count).all()
            for hist in recent:
                if check_password_hash(hist.password_hash, password):
                    raise ValueError(f'Cannot reuse any of your last {history_count} passwords')
        new_hash = generate_password_hash(password)
        self.password_hash = new_hash
        if self.id:
            db.session.add(PasswordHistory(user_id=self.id, password_hash=new_hash))

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.role == 'Admin'

    def is_account_locked(self):
        if not self.locked_until:
            return False
        lu = self.locked_until.replace(tzinfo=timezone.utc) if self.locked_until.tzinfo is None else self.locked_until
        return datetime.now(timezone.utc) < lu

    def record_failed_login(self):
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= app.config.get('LOGIN_MAX_ATTEMPTS', 5):
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=app.config.get('LOGIN_LOCKOUT_MINUTES', 15))
        db.session.commit()

    def reset_failed_attempts(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.now(timezone.utc)
        db.session.commit()


class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)

class Workflow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), nullable=False, default='Created')
    priority = db.Column(db.String(20), nullable=False, default='Medium')
    due_date = db.Column(db.DateTime, nullable=True)
    attachment = db.Column(db.String(255), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    
    # Advanced features
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    estimated_hours = db.Column(db.Float, nullable=True)
    actual_hours = db.Column(db.Float, nullable=True)
    tags = db.Column(db.Text, nullable=True)
    progress_percentage = db.Column(db.Integer, default=0)
    is_template = db.Column(db.Boolean, default=False)
    parent_workflow_id = db.Column(db.Integer, db.ForeignKey('workflow.id'), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    activity_logs = db.relationship('ActivityLog', backref='workflow', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('WorkflowComment', backref='workflow', lazy=True, cascade='all, delete-orphan')
    subtasks = db.relationship('Workflow', backref=db.backref('parent_workflow', remote_side=[id]), lazy='dynamic')
    
    def is_overdue(self):
        """Check if workflow is overdue"""
        if self.due_date and self.status not in ['Completed', 'Cancelled']:
            now = datetime.now(timezone.utc)
            # If due_date is naive (no timezone), assume it's UTC
            if self.due_date.tzinfo is None:
                due_date_utc = self.due_date.replace(tzinfo=timezone.utc)
            else:
                due_date_utc = self.due_date
            return now > due_date_utc
        return False
    
    def get_tags(self):
        """Get tags as list"""
        if self.tags:
            try:
                return json.loads(self.tags)
            except:
                return []
        return []
    
    def set_tags(self, tags_list):
        """Set tags from list"""
        self.tags = json.dumps(tags_list) if tags_list else None
    
    def get_completion_rate(self):
        """Calculate completion rate based on subtasks"""
        if not self.subtasks.count():
            return self.progress_percentage
        
        completed = self.subtasks.filter_by(status='Completed').count()
        total = self.subtasks.count()
        return int((completed / total) * 100) if total > 0 else 0

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workflow_id = db.Column(db.Integer, db.ForeignKey('workflow.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    old_status = db.Column(db.String(50), nullable=True)
    new_status = db.Column(db.String(50), nullable=True)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(200), nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)


class WorkflowComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    workflow_id = db.Column(db.Integer, db.ForeignKey('workflow.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)


class WorkflowAutomation(db.Model):
    """Automation rules for workflows"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    trigger_type = db.Column(db.String(50), nullable=False)  # 'status_change', 'due_date', 'assignment'
    trigger_condition = db.Column(db.Text, nullable=True)  # JSON condition
    action_type = db.Column(db.String(50), nullable=False)  # 'notify', 'assign', 'update_status', 'create_subtask'
    action_params = db.Column(db.Text, nullable=True)  # JSON parameters
    is_active = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)


class WorkflowTemplate(db.Model):
    """Reusable workflow templates"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=True)
    priority = db.Column(db.String(20), nullable=False, default='Medium')
    estimated_hours = db.Column(db.Float, nullable=True)
    checklist_items = db.Column(db.Text, nullable=True)  # JSON array of checklist items
    tags = db.Column(db.Text, nullable=True)  # JSON string of tags
    is_public = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    usage_count = db.Column(db.Integer, default=0)
    
    def get_tags(self):
        if self.tags:
            try:
                return json.loads(self.tags)
            except:
                return []
        return []
    
    def set_tags(self, tags_list):
        """Set tags from list"""
        self.tags = json.dumps(tags_list) if tags_list else None
    
    def get_checklist(self):
        if self.checklist_items:
            try:
                return json.loads(self.checklist_items)
            except:
                return []
        return []
    
    def set_checklist(self, checklist_list):
        """Set checklist items from list"""
        self.checklist_items = json.dumps(checklist_list) if checklist_list else None


class WorkflowAnalytics(db.Model):
    """Analytics data for workflows"""
    id = db.Column(db.Integer, primary_key=True)
    workflow_id = db.Column(db.Integer, db.ForeignKey('workflow.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    views_count = db.Column(db.Integer, default=0)
    comments_count = db.Column(db.Integer, default=0)
    time_spent_minutes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    
    workflow = db.relationship('Workflow', backref='analytics')

# ==================== AUTOMATION FUNCTIONS ====================

def trigger_automations(workflow, trigger_type, trigger_data=None):
    """Trigger automation rules based on workflow events"""
    automations = WorkflowAutomation.query.filter_by(
        trigger_type=trigger_type,
        is_active=True
    ).all()
    
    for automation in automations:
        try:
            if evaluate_condition(automation.trigger_condition, workflow, trigger_data):
                execute_action(automation, workflow, trigger_data)
        except Exception as e:
            app.logger.error(f"Automation error: {e}")

def evaluate_condition(condition_json, workflow, trigger_data):
    """Evaluate automation trigger conditions"""
    if not condition_json:
        return True
    
    try:
        condition = json.loads(condition_json)
        
        # Status change conditions
        if condition.get('status'):
            return workflow.status == condition['status']
        
        # Priority conditions
        if condition.get('priority'):
            return workflow.priority == condition['priority']
        
        # Due date conditions
        if condition.get('due_days'):
            if workflow.due_date:
                days_until_due = (workflow.due_date.date() - datetime.now(timezone.utc).date()).days
                return days_until_due <= condition['due_days']
        
        # Assignment conditions
        if condition.get('assigned_to'):
            return workflow.assigned_to == condition['assigned_to']
            
    except:
        return False
    
    return True

def execute_action(automation, workflow, trigger_data):
    """Execute automation actions"""
    try:
        params = json.loads(automation.action_params or '{}')
        
        if automation.action_type == 'notify':
            # Send notification
            user_id = params.get('user_id', workflow.created_by)
            message = params.get('message', f'Automation: {automation.name} triggered for "{workflow.title}"')
            
            notification = Notification(
                user_id=user_id,
                message=message,
                link=f'/workflow/{workflow.id}'
            )
            db.session.add(notification)
        
        elif automation.action_type == 'assign':
            # Auto-assign workflow
            assign_to_id = params.get('assign_to_id')
            if assign_to_id:
                workflow.assigned_to = assign_to_id
                
                # Notify assignee
                notification = Notification(
                    user_id=assign_to_id,
                    message=f'You have been assigned to workflow: "{workflow.title}"',
                    link=f'/workflow/{workflow.id}'
                )
                db.session.add(notification)
        
        elif automation.action_type == 'update_status':
            # Auto-update status
            new_status = params.get('status')
            if new_status and new_status in WORKFLOW_STATUSES:
                old_status = workflow.status
                workflow.status = new_status
                
                # Log the change
                log = ActivityLog(
                    workflow_id=workflow.id,
                    user_id=None,  # System automation
                    action='Auto Status Change',
                    old_status=old_status,
                    new_status=new_status,
                    details=f'Automation rule: {automation.name}'
                )
                db.session.add(log)
        
        elif automation.action_type == 'create_subtask':
            # Create subtask
            subtask_title = params.get('title', f'Subtask for {workflow.title}')
            subtask = Workflow(
                title=subtask_title,
                description=params.get('description', ''),
                created_by=automation.created_by,
                parent_workflow_id=workflow.id,
                status='Created'
            )
            db.session.add(subtask)
        
        db.session.commit()
        
    except Exception as e:
        app.logger.error(f"Action execution error: {e}")
        db.session.rollback()

# ==================== HELPERS ====================

@app.context_processor
def inject_globals():
    unread = 0
    if is_logged_in():
        try:
            unread = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
        except Exception:
            pass
    return dict(unread_notifications=unread)


def is_logged_in():
    return 'user_id' in session

def get_current_user():
    if is_logged_in():
        return User.query.get(session['user_id'])
    return None

def require_login(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def require_admin(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            flash('Please log in first', 'warning')
            return redirect(url_for('login'))
        user = get_current_user()
        if not user.is_admin():
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper

# ==================== ROUTES ====================

@app.route('/test-email')
@require_login
@require_admin
def test_email():
    """Test email configuration"""
    user = get_current_user()
    if not user.email:
        flash('Please add your email address in your profile first', 'warning')
        return redirect(url_for('profile'))
    
    success = send_workflow_email(
        user.email,
        '🧪 Test Email from Workflow Platform',
        f'''Hello {user.username},

This is a test email to verify your email configuration is working.

If you receive this email, your SMTP settings are correct!

Best regards,
Workflow Platform
        '''
    )
    
    if success:
        flash('Test email sent successfully! Check your inbox.', 'success')
    else:
        flash('Failed to send test email. Check server console for error details.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr or '127.0.0.1'
        if not _rate_limit_login(ip):
            flash('Too many login attempts. Try again in a minute.', 'danger')
            return render_template('login.html')
        username = sanitize_str(request.form.get('username'), app.config.get('USERNAME_MAX_LENGTH', 80))
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
                flash('Account is temporarily locked due to too many failed attempts. Try again later.', 'danger')
                return render_template('login.html')
            user.reset_failed_attempts()
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        if user:
            user.record_failed_login()
            if user.is_account_locked():
                flash('Too many failed attempts — account locked for 15 minutes.', 'danger')
                return render_template('login.html')
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
                        db.session.commit()
                        flash('Password updated successfully', 'success')
                    except ValueError as e:
                        flash(str(e), 'danger')
        elif action == 'email':
            raw = request.form.get('email', '')
            email = sanitize_str(raw, app.config.get('EMAIL_MAX_LENGTH', 120)) or None
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
        overdue_count = Workflow.query.filter(
            Workflow.is_deleted == False,
            Workflow.due_date < datetime.now(timezone.utc),
            Workflow.status.notin_(['Completed', 'Cancelled'])
        ).count()
    else:
        recent_workflows = Workflow.query.filter_by(created_by=user.id, is_deleted=False).order_by(Workflow.updated_at.desc()).limit(5).all()
        total_workflows = Workflow.query.filter_by(created_by=user.id, is_deleted=False).count()
        overdue_count = Workflow.query.filter(
            Workflow.created_by == user.id,
            Workflow.is_deleted == False,
            Workflow.due_date < datetime.now(timezone.utc),
            Workflow.status.notin_(['Completed', 'Cancelled'])
        ).count()
    
    due_soon_days = app.config.get('DUE_SOON_DAYS', 3)
    now = datetime.now(timezone.utc)
    soon_end = now + timedelta(days=due_soon_days)
    if user.is_admin():
        due_soon_workflows = Workflow.query.filter(
            Workflow.due_date != None,
            Workflow.due_date >= now,
            Workflow.due_date <= soon_end,
            Workflow.status.notin_(['Completed', 'Cancelled'])
        ).all()
    else:
        due_soon_workflows = Workflow.query.filter(
            Workflow.created_by == user.id,
            Workflow.due_date != None,
            Workflow.due_date >= now,
            Workflow.due_date <= soon_end,
            Workflow.status.notin_(['Completed', 'Cancelled'])
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
        query = Workflow.query.filter(
            Workflow.is_deleted == False,
            or_(Workflow.created_by == user.id, Workflow.assigned_to == user.id)
        )
    
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
            Workflow.due_date < datetime.now(timezone.utc),
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
def create_workflow():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        priority = request.form.get('priority', 'Medium')
        due_date_str = request.form.get('due_date')
        assigned_to = request.form.get('assigned_to')
        
        category = sanitize_str(request.form.get('category'), 50) or None
        if category and category not in WORKFLOW_CATEGORIES:
            category = None
        if not title:
            flash('Title is required', 'danger')
            users = User.query.filter_by(is_active=True).all()
            return render_template('create_workflow.html', priorities=PRIORITY_LEVELS, categories=WORKFLOW_CATEGORIES, users=users)
        due_date = None
        if due_date_str:
            try:
                due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
                # Make it timezone-aware (assume UTC)
                due_date = due_date.replace(tzinfo=timezone.utc)
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
        
        # Handle assignment
        assigned_to_id = None
        if assigned_to and assigned_to != '':
            try:
                assigned_to_id = int(assigned_to)
                # Verify the assigned user exists and is active
                assigned_user = User.query.filter_by(id=assigned_to_id, is_active=True).first()
                if not assigned_user:
                    flash('Invalid user assignment', 'warning')
                    assigned_to_id = None
            except ValueError:
                flash('Invalid user assignment', 'warning')
                assigned_to_id = None
        
        workflow = Workflow(
            title=title, 
            description=description, 
            category=category,
            status='Created',
            priority=priority,
            due_date=due_date,
            attachment=attachment_path,
            created_by=user.id,
            assigned_to=assigned_to_id
        )
        db.session.add(workflow)
        db.session.flush()
        
        # NEW! Add due date to log details
        details = f'Priority: {priority}'
        if due_date:
            details += f', Due: {due_date.strftime("%Y-%m-%d")}'
        if assigned_to_id:
            assigned_user = User.query.get(assigned_to_id)
            details += f', Assigned to: {assigned_user.username}'
        
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
        
        # Send notification to assigned user
        if assigned_to_id and assigned_to_id != user.id:
            assigned_user = User.query.get(assigned_to_id)
            if assigned_user:
                n_assigned = Notification(
                    user_id=assigned_to_id, 
                    message=f'Workflow "{title}" assigned to you by {user.username}', 
                    link=f'/workflow/{workflow.id}'
                )
                db.session.add(n_assigned)
                
                # Send email notification
                if assigned_user.email:
                    subject = f"📋 New Workflow Assigned: '{title}'"
                    body = f"""
Hello {assigned_user.username},

A new workflow has been assigned to you:

Workflow: {title}
Assigned by: {user.username}
Priority: {priority}
Due Date: {due_date.strftime('%Y-%m-%d') if due_date else 'No due date'}
Description: {description or 'No description'}

Please review and start working on this workflow.

Best regards,
Workflow Platform
                    """
                    send_workflow_email(assigned_user.email, subject, body)
        
        db.session.commit()
        
        flash('Workflow created successfully', 'success')
        return redirect(url_for('workflow_detail', workflow_id=workflow.id))
    
    users = User.query.filter_by(is_active=True).all()
    return render_template('create_workflow.html', priorities=PRIORITY_LEVELS, categories=WORKFLOW_CATEGORIES, users=users)

@app.route('/workflow/<int:workflow_id>')
@require_login
def workflow_detail(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    
    if not user.is_admin() and workflow.created_by != user.id and workflow.assigned_to != user.id:
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
def update_workflow(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    
    if not user.is_admin() and workflow.created_by != user.id and workflow.assigned_to != user.id:
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
            # Make it timezone-aware (assume UTC)
            workflow.due_date = workflow.due_date.replace(tzinfo=timezone.utc)
        except:
            flash('Invalid date format', 'warning')
    
    workflow.updated_at = datetime.now(timezone.utc)
    
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
def add_workflow_comment(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    if not user.is_admin() and workflow.created_by != user.id and workflow.assigned_to != user.id:
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
def delete_workflow(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    if not user.is_admin() and workflow.created_by != user.id:
        flash('You do not have permission to delete this workflow', 'danger')
        return redirect(url_for('workflows'))
    workflow.is_deleted = True
    workflow.deleted_at = datetime.now(timezone.utc)
    workflow.deleted_by = user.id
    db.session.commit()
    flash('Workflow deleted', 'success')
    return redirect(url_for('workflows'))

@app.route('/uploads/<filename>')
@require_login
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/notifications')
@require_login
def notifications():
    user = get_current_user()
    notifs = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(50).all()
    # Mark all as read when page is opened
    Notification.query.filter_by(user_id=user.id, is_read=False).update({'is_read': True})
    db.session.commit()
    return render_template('notifications.html', notifications=notifs)

@app.route('/workflows/export')
@require_login
def export_workflows():
    user = get_current_user()
    if user.is_admin():
        q = Workflow.query.order_by(Workflow.updated_at.desc())
    else:
        q = Workflow.query.filter_by(created_by=user.id).order_by(Workflow.updated_at.desc())
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
        w.writerow(['Total Workflows', Workflow.query.count()])
        w.writerow(['Total Users', User.query.count()])
        w.writerow(['Total Activities', ActivityLog.query.count()])
        for status in WORKFLOW_STATUSES:
            c = Workflow.query.filter_by(status=status).count()
            w.writerow([f'Status: {status}', c])
        for pri in PRIORITY_LEVELS:
            c = Workflow.query.filter_by(priority=pri).count()
            w.writerow([f'Priority: {pri}', c])
    else:
        w.writerow(['My Workflows', Workflow.query.filter_by(created_by=user.id).count()])
        w.writerow(['My Activities', ActivityLog.query.filter_by(user_id=user.id).count()])
        for status in WORKFLOW_STATUSES:
            c = Workflow.query.filter_by(created_by=user.id, status=status).count()
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
def api_list_workflows():
    user = get_current_user()
    if user.is_admin():
        q = Workflow.query.order_by(Workflow.updated_at.desc())
    else:
        q = Workflow.query.filter_by(created_by=user.id).order_by(Workflow.updated_at.desc())
    status = request.args.get('status')
    if status and status in WORKFLOW_STATUSES:
        q = q.filter_by(status=status)
    limit = min(request.args.get('limit', 50, type=int), 100)
    workflows = q.limit(limit).all()
    return jsonify({'workflows': [_api_workflow_to_dict(w) for w in workflows]})

@app.route(f'{API_PREFIX}/workflows/<int:workflow_id>', methods=['GET'])
@require_login
def api_get_workflow(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    if not user.is_admin() and workflow.created_by != user.id:
        return jsonify({'error': 'Forbidden'}), 403
    return jsonify(_api_workflow_to_dict(workflow))

@app.route(f'{API_PREFIX}/workflows', methods=['POST'])
@require_login
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
    workflow.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify(_api_workflow_to_dict(workflow))

@app.route(f'{API_PREFIX}/workflows/<int:workflow_id>', methods=['DELETE'])
@require_login
def api_delete_workflow(workflow_id):
    workflow = Workflow.query.get_or_404(workflow_id)
    user = get_current_user()
    if not user.is_admin() and workflow.created_by != user.id:
        return jsonify({'error': 'Forbidden'}), 403
    db.session.delete(workflow)
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
def create_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip() or None
        role = request.form.get('role', 'User')
        
        username = sanitize_str(username, app.config.get('USERNAME_MAX_LENGTH', 80))
        email = sanitize_str(email, app.config.get('EMAIL_MAX_LENGTH', 120)) or None
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
            user.set_password(password)
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('users'))
    
    return render_template('edit_user.html', user=user, roles=USER_ROLES)

@app.route('/user/<int:user_id>/delete', methods=['POST'])
@require_login
@require_admin
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    current = get_current_user()
    
    if user.id == current.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('users'))
    
    # Check if user has workflows
    workflow_count = Workflow.query.filter_by(created_by=user.id).count()
    if workflow_count > 0:
        flash(f'Cannot delete user "{user.username}" - they have {workflow_count} workflows. Transfer or delete workflows first.', 'danger')
        return redirect(url_for('users'))
    
    # Delete user's notifications, activity logs, and other related data
    Notification.query.filter_by(user_id=user.id).delete()
    ActivityLog.query.filter_by(user_id=user.id).delete()
    WorkflowComment.query.filter_by(user_id=user.id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{user.username}" has been deleted successfully', 'success')
    return redirect(url_for('users'))

@app.route('/user/<int:user_id>/toggle', methods=['POST'])
@require_login
@require_admin
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

# ==================== ADVANCED FEATURES ROUTES ====================

@app.route('/templates')
@require_login
def templates():
    user = get_current_user()
    page = request.args.get('page', 1, type=int)
    if page < 1:
        page = 1
    
    if user.is_admin():
        query = WorkflowTemplate.query
    else:
        query = WorkflowTemplate.query.filter(
            (WorkflowTemplate.created_by == user.id) | (WorkflowTemplate.is_public == True)
        )
    
    pagination = query.order_by(WorkflowTemplate.usage_count.desc()).paginate(
        page=page, per_page=ITEMS_PER_PAGE, error_out=False
    )
    
    return render_template('templates.html', templates=pagination.items, pagination=pagination)

@app.route('/templates/new', methods=['GET', 'POST'])
@require_login
def new_template():
    user = get_current_user()
    if request.method == 'POST':
        name = sanitize_str(request.form.get('name'), 100)
        description = sanitize_str(request.form.get('description'), 1000)
        category = sanitize_str(request.form.get('category'), 50)
        priority = request.form.get('priority', 'Medium')
        estimated_hours = request.form.get('estimated_hours')
        checklist = request.form.getlist('checklist_items')
        tags = request.form.get('tags', '').split(',')
        is_public = request.form.get('is_public') == 'on'
        
        if not name:
            flash('Template name is required', 'danger')
            return render_template('edit_template.html', 
                                 categories=WORKFLOW_CATEGORIES,
                                 priorities=PRIORITY_LEVELS)
        
        template = WorkflowTemplate(
            name=name,
            description=description,
            category=category if category in WORKFLOW_CATEGORIES else None,
            priority=priority if priority in PRIORITY_LEVELS else 'Medium',
            estimated_hours=float(estimated_hours) if estimated_hours else None,
            created_by=user.id,
            is_public=is_public
        )
        
        template.set_checklist([item.strip() for item in checklist if item.strip()])
        template.set_tags([tag.strip() for tag in tags if tag.strip()])
        
        db.session.add(template)
        db.session.commit()
        flash('Template created successfully!', 'success')
        return redirect(url_for('templates'))
    
    return render_template('edit_template.html', 
                         categories=WORKFLOW_CATEGORIES,
                         priorities=PRIORITY_LEVELS)

@app.route('/templates/<int:template_id>/edit', methods=['GET', 'POST'])
@require_login
def edit_template(template_id):
    user = get_current_user()
    template = WorkflowTemplate.query.get_or_404(template_id)
    
    # Check permissions
    if not template.is_public and template.created_by != user.id and not user.is_admin():
        flash('Access denied', 'danger')
        return redirect(url_for('templates'))
    
    if request.method == 'POST':
        name = sanitize_str(request.form.get('name'), 100)
        description = sanitize_str(request.form.get('description'), 1000)
        category = sanitize_str(request.form.get('category'), 50)
        priority = request.form.get('priority', 'Medium')
        estimated_hours = request.form.get('estimated_hours')
        checklist = request.form.getlist('checklist_items')
        tags = request.form.get('tags', '').split(',')
        is_public = request.form.get('is_public') == 'on'
        
        if not name:
            flash('Template name is required', 'danger')
            return render_template('edit_template.html', 
                                 template=template,
                                 categories=WORKFLOW_CATEGORIES,
                                 priorities=PRIORITY_LEVELS)
        
        template.name = name
        template.description = description
        template.category = category if category in WORKFLOW_CATEGORIES else None
        template.priority = priority if priority in PRIORITY_LEVELS else 'Medium'
        template.estimated_hours = float(estimated_hours) if estimated_hours else None
        template.is_public = is_public
        
        template.set_checklist([item.strip() for item in checklist if item.strip()])
        template.set_tags([tag.strip() for tag in tags if tag.strip()])
        
        db.session.commit()
        flash('Template updated successfully!', 'success')
        return redirect(url_for('templates'))
    
    return render_template('edit_template.html', 
                         template=template,
                         categories=WORKFLOW_CATEGORIES,
                         priorities=PRIORITY_LEVELS)

@app.route('/workflow/create-from-template/<int:template_id>')
@require_login
def create_from_template(template_id):
    user = get_current_user()
    template = WorkflowTemplate.query.get_or_404(template_id)
    
    # Check permissions
    if not template.is_public and template.created_by != user.id and not user.is_admin():
        flash('Access denied', 'danger')
        return redirect(url_for('templates'))
    
    # Create workflow from template
    workflow = Workflow(
        title=template.name,
        description=template.description,
        category=template.category,
        priority=template.priority,
        estimated_hours=template.estimated_hours,
        created_by=user.id,
        tags=template.tags
    )
    
    db.session.add(workflow)
    db.session.flush()  # Get workflow ID
    
    # Create checklist items as subtasks
    for item in template.get_checklist():
        subtask = Workflow(
            title=item,
            created_by=user.id,
            parent_workflow_id=workflow.id,
            status='Created'
        )
        db.session.add(subtask)
    
    # Update template usage count
    template.usage_count += 1
    
    db.session.commit()
    
    # Trigger automations
    trigger_automations(workflow, 'status_change', {'status': 'Created'})
    
    flash(f'Workflow "{template.name}" created from template!', 'success')
    return redirect(url_for('workflow_detail', workflow_id=workflow.id))

@app.route('/automation')
@require_login
@require_admin
def automation():
    user = get_current_user()
    automations = WorkflowAutomation.query.filter_by(created_by=user.id).all()
    return render_template('automation.html', automations=automations)

@app.route('/automation/<int:automation_id>/toggle', methods=['POST'])
@require_login
@require_admin
def toggle_automation(automation_id):
    automation = WorkflowAutomation.query.get_or_404(automation_id)
    automation.is_active = not automation.is_active
    db.session.commit()
    return '', 204

@app.route('/automation/<int:automation_id>/edit', methods=['GET', 'POST'])
@require_login
@require_admin
def edit_automation(automation_id):
    user = get_current_user()
    automation = WorkflowAutomation.query.get_or_404(automation_id)
    
    if request.method == 'POST':
        name = sanitize_str(request.form.get('name'), 100)
        trigger_type = request.form.get('trigger_type')
        action_type = request.form.get('action_type')
        
        # Build condition JSON
        condition = {}
        if request.form.get('condition_status'):
            condition['status'] = request.form.get('condition_status')
        if request.form.get('condition_priority'):
            condition['priority'] = request.form.get('condition_priority')
        if request.form.get('condition_due_days'):
            condition['due_days'] = int(request.form.get('condition_due_days'))
        if request.form.get('condition_assigned_to'):
            condition['assigned_to'] = int(request.form.get('condition_assigned_to'))
        
        # Build action parameters JSON
        action_params = {}
        if action_type == 'notify':
            action_params['message'] = request.form.get('notify_message', '')
        elif action_type == 'assign':
            action_params['assign_to_id'] = int(request.form.get('assign_to_id'))
        elif action_type == 'update_status':
            action_params['status'] = request.form.get('update_status')
        elif action_type == 'create_subtask':
            action_params['title'] = request.form.get('subtask_title', '')
            action_params['description'] = request.form.get('subtask_description', '')
        
        if not name or not trigger_type or not action_type:
            flash('Name, trigger type, and action type are required', 'danger')
            return render_template('edit_automation.html',
                                 automation=automation,
                                 users=User.query.filter_by(is_active=True).all(),
                                 user_choices=[{'id': u.id, 'username': u.username} for u in User.query.filter_by(is_active=True).all()],
                                 statuses=WORKFLOW_STATUSES,
                                 priorities=PRIORITY_LEVELS)
        
        automation.name = name
        automation.trigger_type = trigger_type
        automation.trigger_condition = json.dumps(condition) if condition else None
        automation.action_type = action_type
        automation.action_params = json.dumps(action_params) if action_params else None
        
        db.session.commit()
        flash('Automation rule updated successfully!', 'success')
        return redirect(url_for('automation'))
    
    return render_template('edit_automation.html',
                         automation=automation,
                         users=User.query.filter_by(is_active=True).all(),
                         user_choices=[{'id': u.id, 'username': u.username} for u in User.query.filter_by(is_active=True).all()],
                         statuses=WORKFLOW_STATUSES,
                         priorities=PRIORITY_LEVELS)

@app.route('/automation/<int:automation_id>/delete', methods=['POST'])
@require_login
@require_admin
def delete_automation(automation_id):
    automation = WorkflowAutomation.query.get_or_404(automation_id)
    db.session.delete(automation)
    db.session.commit()
    return '', 204

@app.route('/automation/new', methods=['GET', 'POST'])
@require_login
@require_admin
def new_automation():
    user = get_current_user()
    if request.method == 'POST':
        name = sanitize_str(request.form.get('name'), 100)
        trigger_type = request.form.get('trigger_type')
        action_type = request.form.get('action_type')
        
        # Build condition JSON
        condition = {}
        if request.form.get('condition_status'):
            condition['status'] = request.form.get('condition_status')
        if request.form.get('condition_priority'):
            condition['priority'] = request.form.get('condition_priority')
        if request.form.get('condition_due_days'):
            condition['due_days'] = int(request.form.get('condition_due_days'))
        if request.form.get('condition_assigned_to'):
            condition['assigned_to'] = int(request.form.get('condition_assigned_to'))
        
        # Build action parameters JSON
        action_params = {}
        if action_type == 'notify':
            action_params['message'] = request.form.get('notify_message', '')
        elif action_type == 'assign':
            action_params['assign_to_id'] = int(request.form.get('assign_to_id'))
        elif action_type == 'update_status':
            action_params['status'] = request.form.get('update_status')
        elif action_type == 'create_subtask':
            action_params['title'] = request.form.get('subtask_title', '')
            action_params['description'] = request.form.get('subtask_description', '')
        
        if not name or not trigger_type or not action_type:
            flash('Name, trigger type, and action type are required', 'danger')
            return render_template('edit_automation.html',
                                 users=User.query.filter_by(is_active=True).all(),
                                 user_choices=[{'id': u.id, 'username': u.username} for u in User.query.filter_by(is_active=True).all()],
                                 statuses=WORKFLOW_STATUSES,
                                 priorities=PRIORITY_LEVELS)
        
        automation = WorkflowAutomation(
            name=name,
            trigger_type=trigger_type,
            trigger_condition=json.dumps(condition) if condition else None,
            action_type=action_type,
            action_params=json.dumps(action_params) if action_params else None,
            created_by=user.id
        )
        
        db.session.add(automation)
        db.session.commit()
        flash('Automation rule created successfully!', 'success')
        return redirect(url_for('automation'))
    
    return render_template('edit_automation.html',
                         users=User.query.filter_by(is_active=True).all(),
                         user_choices=[{'id': u.id, 'username': u.username} for u in User.query.filter_by(is_active=True).all()],
                         statuses=WORKFLOW_STATUSES,
                         priorities=PRIORITY_LEVELS)

@app.route('/analytics')
@require_login
def analytics():
    user = get_current_user()
    
    # Get date range
    days = request.args.get('days', 30, type=int)
    start_date = datetime.now(timezone.utc) - timedelta(days=days)
    page = request.args.get('page', 1, type=int)
    
    if user.is_admin():
        # Admin analytics
        total_workflows = Workflow.query.count()
        total_users = User.query.count()
        total_activities = ActivityLog.query.count()
        
        # Workflow stats by status
        status_stats = {}
        for status in WORKFLOW_STATUSES:
            count = Workflow.query.filter_by(status=status).count()
            status_stats[status] = count
        
        # Priority distribution
        priority_stats = {}
        for priority in PRIORITY_LEVELS:
            count = Workflow.query.filter_by(priority=priority).count()
            priority_stats[priority] = count
        
        # Recent activity trend
        activity_trend = []
        for i in range(days):
            date = (datetime.now(timezone.utc) - timedelta(days=i)).date()
            count = ActivityLog.query.filter(
                ActivityLog.timestamp >= date,
                ActivityLog.timestamp < date + timedelta(days=1)
            ).count()
            activity_trend.append({'date': date.isoformat(), 'count': count})
        
        # Top performers
        top_creators = db.session.query(
            User.username, func.count(Workflow.id).label('workflow_count')
        ).join(Workflow, User.id == Workflow.created_by).group_by(User.id).order_by(
            func.count(Workflow.id).desc()
        ).limit(5).all()
        
        # Activity logs for admin
        logs_query = ActivityLog.query.order_by(ActivityLog.timestamp.desc())
        recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
        
    else:
        # User analytics
        total_workflows = Workflow.query.filter_by(created_by=user.id).count()
        total_activities = ActivityLog.query.filter_by(user_id=user.id).count()
        total_users = 1
        
        # User's workflow stats
        status_stats = {}
        for status in WORKFLOW_STATUSES:
            count = Workflow.query.filter_by(created_by=user.id, status=status).count()
            status_stats[status] = count
        
        # User's priority distribution
        priority_stats = {}
        for priority in PRIORITY_LEVELS:
            count = Workflow.query.filter_by(created_by=user.id, priority=priority).count()
            priority_stats[priority] = count
        
        # User's activity trend
        activity_trend = []
        for i in range(days):
            date = (datetime.now(timezone.utc) - timedelta(days=i)).date()
            count = ActivityLog.query.filter(
                ActivityLog.user_id == user.id,
                ActivityLog.timestamp >= date,
                ActivityLog.timestamp < date + timedelta(days=1)
            ).count()
            activity_trend.append({'date': date.isoformat(), 'count': count})
        
        top_creators = []
        
        # Activity logs for user
        logs_query = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.timestamp.desc())
        recent_logs = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    # Paginate logs
    logs_pagination = logs_query.paginate(page=page, per_page=ITEMS_PER_PAGE, error_out=False)
    
    return render_template('analytics.html',
                         total_workflows=total_workflows,
                         total_users=total_users if user.is_admin() else 1,
                         total_activities=total_activities,
                         status_dict=status_stats,
                         priority_dict=priority_stats,
                         activity_trend=list(reversed(activity_trend)),
                         top_creators=top_creators,
                         days=days,
                         recent_logs=recent_logs,
                         logs_pagination=logs_pagination)

# ==================== INIT ====================

def migrate_db():
    """Safely add new columns — never drops data."""
    from sqlalchemy import text
    tbl_user = User.__table__.name
    tbl_workflow = Workflow.__table__.name
    migrations = [
        f'ALTER TABLE "{tbl_user}" ADD COLUMN email VARCHAR(120)',
        f'ALTER TABLE "{tbl_user}" ADD COLUMN is_active INTEGER DEFAULT 1',
        f'ALTER TABLE "{tbl_user}" ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP',
        f'ALTER TABLE "{tbl_user}" ADD COLUMN last_login DATETIME',
        f'ALTER TABLE "{tbl_user}" ADD COLUMN failed_login_attempts INTEGER DEFAULT 0',
        f'ALTER TABLE "{tbl_user}" ADD COLUMN locked_until DATETIME',
        f'ALTER TABLE "{tbl_workflow}" ADD COLUMN attachment VARCHAR(255)',
        f'ALTER TABLE "{tbl_workflow}" ADD COLUMN category VARCHAR(50)',
        f'ALTER TABLE "{tbl_workflow}" ADD COLUMN is_deleted INTEGER DEFAULT 0',
        f'ALTER TABLE "{tbl_workflow}" ADD COLUMN deleted_at DATETIME',
        f'ALTER TABLE "{tbl_workflow}" ADD COLUMN deleted_by INTEGER',
    ]
    for col_sql in migrations:
        try:
            db.session.execute(text(col_sql))
            db.session.commit()
        except Exception:
            db.session.rollback()  # column already exists — safe to skip

def init_db():
    with app.app_context():
        db.create_all()
        migrate_db()
        if User.query.first() is None:
            admin = User(username='admin', role='Admin')
            admin.password_hash = generate_password_hash('Admin@123456!')
            db.session.add(admin)
            db.session.flush()
            db.session.add(PasswordHistory(user_id=admin.id, password_hash=admin.password_hash))

            user = User(username='user', role='User')
            user.password_hash = generate_password_hash('User@123456!')
            db.session.add(user)
            db.session.flush()
            db.session.add(PasswordHistory(user_id=user.id, password_hash=user.password_hash))

            db.session.commit()
            print("\n" + "="*50)
            print("[OK] DATABASE READY!")
            print("="*50)
            print("  Admin: username=admin  password=Admin@123456!")
            print("  User:  username=user   password=User@123456!")
            print("="*50 + "\n")

if __name__ == '__main__':
    init_db()
    start_scheduler()
    port = int(os.environ.get('PORT', 5000))
    print(f"Server starting at http://0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=True)