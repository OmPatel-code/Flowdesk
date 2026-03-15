# FlowDesk — Workflow Management System

A full-stack web-based Workflow Management System built with **Python Flask** for BTech IT 6th Semester Mini Project.

## Features

- Role-based access control (Admin / User)
- Create, assign, and track workflows with status, priority, category, and due dates
- Deadline email reminders via Gmail SMTP (APScheduler)
- In-app notification system
- File attachments (PDF, images, docs)
- Reusable workflow templates
- Automation rules (trigger → condition → action)
- Analytics dashboard with Chart.js (status, priority, activity trend)
- CSV export for workflows and analytics
- Full activity audit log
- Password history enforcement + account lockout after failed logins
- Soft delete for workflows
- REST API at `/api/v1/workflows`
- Dark / Light mode toggle (persists via localStorage)

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Flask 3.1 |
| Database | SQLite via SQLAlchemy ORM |
| Templating | Jinja2 |
| Scheduling | APScheduler |
| Password hashing | Werkzeug (bcrypt) |
| Charts | Chart.js (CDN) |
| Frontend | Custom HTML/CSS (no Bootstrap) |

## Setup & Run

```bash
# 1. Clone the repo
git clone https://github.com/OmPatel-code/flowdesk.git
cd flowdesk

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

## Default Login Credentials

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `Admin@123456!` |
| User | `user` | `User@123456!` |

## Email Setup (Optional)

To enable deadline reminders, add your Gmail credentials to `config.py`:

```python
MAIL_USERNAME       = 'your@gmail.com'
MAIL_PASSWORD       = 'your-16-char-app-password'
MAIL_DEFAULT_SENDER = 'your@gmail.com'
```

Get an App Password at: **myaccount.google.com → Security → App Passwords**

## Project Structure

```
workflow_platform/
├── app.py              # Main Flask app — routes, models, scheduler
├── config.py           # All configuration constants
├── requirements.txt    # Python dependencies
├── templates/          # Jinja2 HTML templates (15+ pages)
├── static/             # CSS and static assets
└── uploads/            # User-uploaded file attachments
```

## Database Tables

`User` · `Workflow` · `ActivityLog` · `Notification` · `WorkflowComment` · `WorkflowAutomation` · `WorkflowTemplate` · `WorkflowAnalytics` · `PasswordHistory`

## Security Features

- bcrypt password hashing
- Session-based authentication with HttpOnly cookies
- Rate limiting on login (3 attempts/min per IP)
- Account lockout after 5 failed attempts (15 min)
- Password history — cannot reuse last 5 passwords
- Input sanitization on all form fields
- SQL injection prevention via SQLAlchemy ORM
- Soft delete (data preserved, not destroyed)

---

**Built by Om Patel — BTech IT, 6th Semester Mini Project**
