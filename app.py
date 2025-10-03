# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Ikhlas

import os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort,send_file ,make_response ,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Regexp
from utils.decorators import prevent_back_navigation
import re
import logging
import qrcode
from io import BytesIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_migrate import Migrate
import ssl
from werkzeug.utils import secure_filename

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


def create_app():
    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY', 'your-secret-key'),
        SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL', 'sqlite:///hospital.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(days=365),
        REMEMBER_COOKIE_SECURE=True,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_DURATION=timedelta(days=365),
        SESSION_PERMANENT=True,
        DEBUG=False if os.getenv('FLASK_ENV') == 'production' else True
    )

    return app

# Create app instance
app = create_app()

csrf = CSRFProtect()
csrf.init_app(app)

# Configure CSRF exemption for Twilio webhooks
app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # Disable global CSRF
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit for tokens

UPLOAD_FOLDER = 'static/voice_messages'
ALLOWED_EXTENSIONS = {'mp3', 'wav'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config.update(
    STATIC_FOLDER = 'static',
    STATIC_URL_PATH = '/static'
)

# Create required directories
STATIC_JS_DIR = os.path.join(app.config['STATIC_FOLDER'], 'js')
os.makedirs(STATIC_JS_DIR, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# Configure Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"
login_manager.remember_cookie_duration = timedelta(days=365)

@login_manager.user_loader
def load_user(user_id):
    if user_id is not None:
        return User.query.get(int(user_id))
    return None

# Security headers
talisman = Talisman(
    app,
    force_https=True,
    content_security_policy={
        'default-src': ["'self'", "*.twilio.com", "handler.twilio.com", "api.twilio.com"],
        'script-src': [
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "cdn.jsdelivr.net",
            "cdnjs.cloudflare.com"
        ],
        'style-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
        'font-src': ["'self'", "cdnjs.cloudflare.com"],
        'img-src': ["'self'", "data:", "https:"],
        'connect-src': ["'self'", "*.twilio.com"]
    }
)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Twilio Configuration
account_sid = os.getenv('TWILIO_ACCOUNT_SID')
auth_token = os.getenv('TWILIO_AUTH_TOKEN')
twilio_number = os.getenv('TWILIO_PHONE_NUMBER')

# Initialize Twilio client
ENVIRONMENT = os.getenv('FLASK_ENV', 'production')
try:
    twilio_client = Client(account_sid, auth_token)
    if ENVIRONMENT == 'production':
        account = twilio_client.api.accounts(account_sid).fetch()
        logger.info("Twilio client initialized successfully")
except Exception as e:
    logger.error(f"Error initializing Twilio client: {str(e)}")
    if ENVIRONMENT == 'production':
        raise


# Models
ist_tz = timezone(timedelta(hours=5, minutes=30))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    patients = db.relationship('Patient', backref='doctor', lazy=True)
    voice_message_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # Add these methods for proper user session handling
    def get_id(self):
        return str(self.id)

    def __repr__(self):
        return f'<User {self.username}>'

    @property
    def is_active(self):
        return True

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False, unique=True)  # Add unique constraint
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    last_call = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    qr_registration_enabled = db.Column(db.Boolean, default=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class CallLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    phone_number = db.Column(db.String(20))
    call_sid = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20))
    duration = db.Column(db.Integer, default=0)

class CallRetry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'))
    original_call_sid = db.Column(db.String(50))
    retry_count = db.Column(db.Integer, default=0)
    max_retries = db.Column(db.Integer, default=3)
    last_attempt = db.Column(db.DateTime, default=lambda: datetime.now(ist_tz))
    status = db.Column(db.String(20), default='pending')

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class AddPatientForm(FlaskForm):
    patient_name = StringField('Patient Name', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[
        DataRequired(),
        Regexp(r'^[0-9]{10}$', message='Please enter a valid 10-digit number')
    ])

class AddCompanionForm(FlaskForm):
    patient_name = StringField('Patient Name', validators=[DataRequired()])
    phone = StringField('Phone Number', validators=[
        DataRequired(),
        Regexp(r'^[0-9]{10}$', message='Please enter a valid 10-digit number')
    ])

def init_db():
    """Initialize the database and create default admin user"""
    with app.app_context():
        try:
            # Ensure instance folder exists
            instance_path = os.path.join(os.getcwd(), 'instance')
            if not os.path.exists(instance_path):
                os.makedirs(instance_path)

            # Create all tables
            db.create_all()
            if not Settings.query.first():
                settings = Settings(qr_registration_enabled=True)
                db.session.add(settings)
                db.session.commit()
            # Create default admin user if it doesn't exist
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(
                    username='admin',
                    name='Administrator',
                    password=generate_password_hash('admin123')
                )
                db.session.add(admin)
                db.session.commit()
                logger.info("Default admin user created successfully")

        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
            if ENVIRONMENT == 'production':
                raise
migrate = Migrate(app, db)

def is_phone_unique(phone_number):
    """Check if phone number already exists"""
    existing = Patient.query.filter_by(phone_number=phone_number).first()
    return existing is None

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Security middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            # Make the session permanent
            session.permanent = True

            # Log in the user with remember=True
            login_user(user, remember=True, duration=timedelta(days=365))

            # Update last login time
            user.last_login = datetime.now(ist_tz)
            db.session.commit()

            app.logger.info(f"User {user.username} logged in successfully")

            # Set a session cookie
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie(
                'remember_token',
                value=user.get_id(),
                max_age=31536000,  # 1 year in seconds
                secure=True,
                httponly=True,
                samesite='Lax'
            )
            return response

        flash('Invalid username or password', 'error')
        app.logger.warning(f"Failed login attempt for username: {form.username.data}")

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    app.logger.info(f"User {current_user.username} logged out")
    logout_user()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    settings = Settings.query.first()
    if not settings:
        settings = Settings(qr_registration_enabled=True)
        db.session.add(settings)
        db.session.commit()
    return render_template('dashboard.html', registration_enabled=settings.qr_registration_enabled)


@app.route('/add_patient', methods=['GET', 'POST'])
@login_required
def add_patient():
    form = AddPatientForm()
    if form.validate_on_submit():
        try:
            phone_number = '+91' + form.phone_number.data.strip()

            # Check if phone number already exists
            existing_patient = Patient.query.filter_by(phone_number=phone_number).first()
            if existing_patient:
                flash('A patient with this phone number already exists', 'error')
                return render_template('add_patient.html', form=form)

            new_patient = Patient(
                patient_name=form.patient_name.data,
                phone_number=phone_number,
                doctor_id=current_user.id
            )
            db.session.add(new_patient)
            db.session.commit()

            # Redirect to dashboard with success parameter
            return redirect(url_for('dashboard', success=True))

        except Exception as e:
            db.session.rollback()
            flash(f'Error adding patient: {str(e)}', 'error')

    return render_template('add_patient.html', form=form)

@app.route('/api/make-call', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def make_call():
    try:
        data = request.get_json()
        patient_id = data.get('patient_id')
        if not patient_id:
            return jsonify({'status': 'error', 'message': 'Patient ID is required'})

        patient = Patient.query.get(patient_id)
        if not patient:
            return jsonify({'status': 'error', 'message': 'Patient not found'})

        webhook_url = 'https://handler.twilio.com/twiml/EH20840927b19d43fc54535de7d9eaf33f'
        call = twilio_client.calls.create(
            to=patient.phone_number,
            from_=twilio_number,
            url=webhook_url,
            method='GET',
            status_callback=url_for('call_status_callback', _external=True, _scheme='https'),
            status_callback_event=['initiated', 'ringing', 'answered', 'completed']
        )

        call_log = CallLog(
            doctor_id=current_user.id,
            patient_id=patient.id,
            phone_number=patient.phone_number,
            status='initiated',
            call_sid=call.sid
        )
        db.session.add(call_log)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Call initiated successfully',
            'call_sid': call.sid
        })
    except Exception as e:
        app.logger.error(f"Error in make_call route: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/bulk-call', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def bulk_call():
    try:
        selected_patients = request.get_json().get('patient_ids', [])
        if not selected_patients:
            return jsonify({'status': 'error', 'message': 'No patients selected'})

        calls_initiated = []
        errors = []

        for patient_id in selected_patients:
            try:
                patient = Patient.query.get(patient_id)
                if patient and patient.doctor_id == current_user.id:
                    webhook_url = 'https://handler.twilio.com/twiml/EH20840927b19d43fc54535de7d9eaf33f'

                    # Make the call
                    call = twilio_client.calls.create(
                        to=patient.phone_number,
                        from_=twilio_number,
                        url=webhook_url,
                        method='GET',
                        status_callback=url_for('call_status_callback', _external=True, _scheme='https'),
                        status_callback_event=['initiated', 'ringing', 'answered', 'completed']
                    )

                    # Log the call
                    call_log = CallLog(
                        doctor_id=current_user.id,
                        patient_id=patient.id,
                        phone_number=patient.phone_number,
                        status='initiated',
                        call_sid=call.sid
                    )
                    db.session.add(call_log)

                    calls_initiated.append({
                        'patient_name': patient.patient_name,
                        'phone_number': patient.phone_number,
                        'call_sid': call.sid
                    })

                else:
                    errors.append(f"Patient {patient_id} not found or access denied")

            except Exception as e:
                app.logger.error(f"Error calling patient {patient_id}: {str(e)}")
                errors.append(f"Error calling patient {patient_id}: {str(e)}")
                continue

        # Commit all successful calls
        if calls_initiated:
            db.session.commit()

        # Return response with both successes and errors
        return jsonify({
            'status': 'success' if calls_initiated else 'error',
            'message': f'Initiated {len(calls_initiated)} calls' + (f' with {len(errors)} errors' if errors else ''),
            'calls': calls_initiated,
            'errors': errors if errors else None
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Bulk call error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to process bulk call: {str(e)}'
        }), 500


@app.route('/voice-message', methods=['GET', 'POST'])
@csrf.exempt
def voice_message():
    try:
        # Redirect to Twilio Bin URL
        return redirect('https://handler.twilio.com/twiml/EH20840927b19d43fc54535de7d9eaf33f')
    except Exception as e:
        app.logger.error(f"Error in voice_message: {str(e)}")
        fallback = VoiceResponse()
        fallback.say("Hello, this is a test message.")
        return str(fallback), 200, {'Content-Type': 'text/xml'}

@app.route('/call-status-callback', methods=['POST'])
@csrf.exempt
def call_status_callback():
    try:
        call_sid = request.form.get('CallSid')
        call_status = request.form.get('CallStatus')
        call_duration = request.form.get('CallDuration', 0)

        status_map = {
            'initiated': 'initiated',
            'ringing': 'ringing',
            'in-progress': 'answered',
            'completed': 'completed',
            'busy': 'busy',
            'no-answer': 'no-answer',
            'failed': 'failed',
            'canceled': 'cancelled'
        }

        call_log = CallLog.query.filter_by(call_sid=call_sid).first()
        if call_log:
            current_status = status_map.get(call_status, call_status)
            call_log.status = current_status
            call_log.duration = int(call_duration) if call_duration else 0

            # Check if call needs retry
            if current_status in ['failed', 'busy', 'no-answer']:
                retry = CallRetry.query.filter_by(original_call_sid=call_sid).first()
                if not retry:
                    retry = CallRetry(
                        patient_id=call_log.patient_id,
                        original_call_sid=call_sid,
                        retry_count=0,
                        max_retries=3
                    )
                    db.session.add(retry)

                if retry.retry_count < retry.max_retries:
                    retry.retry_count += 1
                    retry.last_attempt = datetime.now(timezone.utc)

                    # Wait 1 minute before retrying
                    try:
                        patient = Patient.query.get(call_log.patient_id)
                        webhook_url = url_for('voice_message', _external=True, _scheme='https')

                        # Schedule call after 1 minute
                        new_call = twilio_client.calls.create(
                            to=patient.phone_number,
                            from_=twilio_number,
                            url=webhook_url,
                            method='POST',
                            status_callback=url_for('call_status_callback', _external=True, _scheme='https'),
                            status_callback_event=['initiated', 'ringing', 'answered', 'completed']
                        )

                        new_call_log = CallLog(
                            doctor_id=call_log.doctor_id,
                            patient_id=patient.id,
                            phone_number=patient.phone_number,
                            status='initiated',
                            call_sid=new_call.sid
                        )
                        db.session.add(new_call_log)

                    except Exception as e:
                        app.logger.error(f"Error in retry call: {str(e)}")
                else:
                    retry.status = 'failed'

            db.session.commit()

        return jsonify({'status': 'success'}), 200

    except Exception as e:
        logger.error(f"Error in call status callback: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/call-logs')
@login_required
def get_call_logs():
    try:
        # Get the last 100 call logs for the current user
        logs = CallLog.query.filter_by(doctor_id=current_user.id)\
            .join(Patient, CallLog.patient_id == Patient.id)\
            .add_columns(
                CallLog.id,
                CallLog.phone_number,
                CallLog.timestamp,
                CallLog.status,
                CallLog.duration,
                Patient.patient_name
            )\
            .order_by(CallLog.timestamp.desc())\
            .all()

        # Format the logs for JSON response
        formatted_logs = [{
            'id': log.id,
            'patient_name': log.patient_name,
            'phone_number': log.phone_number,
            'timestamp': (log.timestamp + timedelta(hours=5, minutes=30)).strftime('%Y-%m-%d %H:%M:%S'),
            'status': log.status,
            'duration': log.duration or 0
        } for log in logs]

        return jsonify(formatted_logs)

    except Exception as e:
        app.logger.error(f"Error fetching call logs: {str(e)}")
        return jsonify({
            'error': 'Failed to fetch call logs',
            'message': str(e)
        }), 500


@app.route('/api/remove-patient/<int:patient_id>', methods=['DELETE'])
@login_required
def remove_patient(patient_id):
    try:
        patient = Patient.query.get_or_404(patient_id)
        if patient.doctor_id != current_user.id:
            app.logger.warning(f"Unauthorized attempt to remove patient {patient_id} by user {current_user.id}")
            abort(403)

        # Remove associated call logs
        CallLog.query.filter_by(patient_id=patient_id).delete()

        db.session.delete(patient)
        db.session.commit()

        app.logger.info(f"Patient {patient_id} removed by doctor {current_user.username}")
        return jsonify({'status': 'success'})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error removing patient {patient_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/bulk-remove-patients', methods=['DELETE'])
@login_required
def bulk_remove_patients():
    try:
        data = request.get_json()
        patient_ids = data.get('patient_ids', [])

        if not patient_ids:
            return jsonify({'status': 'error', 'message': 'No patients selected'}), 400

        # Verify ownership and delete
        Patient.query.filter(
            Patient.id.in_(patient_ids),
            Patient.doctor_id == current_user.id
        ).delete(synchronize_session=False)

        # Delete associated call logs
        CallLog.query.filter(
            CallLog.patient_id.in_(patient_ids)
        ).delete(synchronize_session=False)

        db.session.commit()

        return jsonify({'status': 'success', 'message': f'Removed {len(patient_ids)} patients'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/register-companion', methods=['GET', 'POST'])
@prevent_back_navigation
def register_companion():
    settings = Settings.query.first()
    if not settings or not settings.qr_registration_enabled:
        return render_template('registration_disabled.html')
    form = AddCompanionForm()
    if form.validate_on_submit():
        try:
            phone_number = form.phone.data.strip()
            if not phone_number.startswith('+91'):
                phone_number = '+91' + phone_number

            if not re.match(r'^\+91[0-9]{10}$', phone_number):
                flash('Please enter a valid 10-digit number')
                return redirect(url_for('register_companion'))

            # Check for duplicate phone number
            if not is_phone_unique(phone_number):
                flash('This phone number is already registered')
                return redirect(url_for('register_companion'))

            doctor = User.query.filter_by(username='admin').first()
            if not doctor:
                flash('System error: No default doctor found')
                return redirect(url_for('register_companion'))

            new_patient = Patient(
                patient_name=form.patient_name.data,
                phone_number=phone_number,
                doctor_id=doctor.id,
                created_at=datetime.now(timezone.utc)
            )

            db.session.add(new_patient)
            db.session.commit()
            app.logger.info(f"New companion registered: {new_patient.patient_name}")

            response = make_response(render_template('registration_success.html'))
            response.headers.update({
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            })
            return response

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.')
            return redirect(url_for('register_companion'))

    return render_template('register_companion.html', form=form)


@app.route('/api/toggle-registration', methods=['POST'])
@login_required
def toggle_registration():
    try:
        settings = Settings.query.first()
        if not settings:
            settings = Settings(qr_registration_enabled=True)
            db.session.add(settings)

        # Toggle the registration status
        settings.qr_registration_enabled = not settings.qr_registration_enabled
        settings.updated_at = datetime.now(timezone.utc)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'enabled': settings.qr_registration_enabled
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error toggling registration: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/download-qr')
def download_qr():
    """Generate and serve QR code for download"""
    # Generate the full URL for companion registration
    registration_url = url_for('register_companion', _external=True)

    # Create QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(registration_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Create a bytes buffer
    buf = BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    return send_file(
        buf,
        mimetype='image/png',
        as_attachment=True,
        download_name='patient_registration_qr.png'
    )

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')

        # Check Twilio connection if in production
        if ENVIRONMENT == 'production':
            twilio_client.api.accounts(account_sid).fetch()

        return jsonify({
            'status': 'healthy',
            'environment': ENVIRONMENT,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500

# Initialize database
init_db()

# Error handlers
@app.errorhandler(400)
def bad_request_error(error):
    app.logger.error(f"400 Error: {error}")
    return jsonify({'status': 'error', 'message': 'Bad request'}), 400


@app.errorhandler(401)
def unauthorized_error(error):
    app.logger.error(f"401 Error: {error}")
    return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401


@app.errorhandler(403)
def forbidden_error(error):
    app.logger.error(f"403 Error: {error}")
    return jsonify({'status': 'error', 'message': 'Forbidden'}), 403


@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f"404 Error: {error}")
    return jsonify({'status': 'error', 'message': 'Not found'}), 404


@app.errorhandler(429)
def ratelimit_error(error):
    app.logger.error(f"429 Error: {error}")
    return jsonify({'status': 'error', 'message': 'Too many requests'}), 429


@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"500 Error: {error}")
    db.session.rollback()
    return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


if __name__ == '__main__':
    if ENVIRONMENT == 'production':
        # Production settings
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(
            certfile=os.getenv('SSL_CERTFILE', 'cert.pem'),
            keyfile=os.getenv('SSL_KEYFILE', 'key.pem')
        )
        app.run(
            host='0.0.0.0',
            port=int(os.getenv('PORT', 5000)),
            ssl_context=ssl_context,
            debug=False
        )
    else:
        # Development settings
        app.run(debug=True)