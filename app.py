# Updated app.py to match your config.json
import os
import json
import math
import random
import datetime
import smtplib
from functools import wraps
from email.message import EmailMessage
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient, GEOSPHERE
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
import certifi
from pymongo import MongoClient

from models import db, Event, Donor
# Initialize Flask app
app = Flask(__name__)

# Load configuration from config.json
with open('config.json') as config_file:
    config = json.load(config_file)
    
app.config.update(
    SECRET_KEY=config['SECRET_KEY'],
    MONGO_URI=config['MONGO_URI'],
    DB_NAME=config['DB_NAME'],
    SMTP_SERVER=config['SMTP_SERVER'],
    SMTP_PORT=config['SMTP_PORT'],
    EMAIL_USER=config['EMAIL_USER'],
    EMAIL_PASSWORD=config['EMAIL_PASSWORD'],
    OTP_EXPIRY_MINUTES=config['OTP_EXPIRY_MINUTES']
)

# MongoDB setup
client = MongoClient(
    app.config['MONGO_URI'],
    tls=True,
    tlsCAFile=certifi.where()
)

db = client[app.config['DB_NAME']]
users_col = db.users
requests_col = db.requests
spam_queue_col = db.spam_queue
alerts_col = db.alerts

# Create geospatial index
users_col.create_index([("location", GEOSPHERE)])

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_data):
        self.data = user_data
    
    def get_id(self):
        return str(self.data['_id'])

@login_manager.user_loader
def load_user(user_id):
    user_data = users_col.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

# Role-based access control
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.data['role'] not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Helper functions
def send_email(to, subject, body):
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg['Subject'] = subject
        msg['From'] = app.config['EMAIL_USER']
        msg['To'] = to
        
        with smtplib.SMTP_SSL(
            app.config['SMTP_SERVER'], 
            app.config['SMTP_PORT']
        ) as server:
            server.login(
                app.config['EMAIL_USER'], 
                app.config['EMAIL_PASSWORD']
            )
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def haversine(lat1, lon1, lat2, lon2):
    # Convert degrees to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    # Earth radius in kilometers
    R = 6371
    return c * R

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form
        required = ['name', 'email', 'phone', 'password', 'confirm_password', 'role']
        
        # Validate required fields
        if any(field not in data or not data[field] for field in required):
            flash('All fields are required', 'danger')
            return redirect(url_for('signup'))
        
        if data['password'] != data['confirm_password']:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('signup'))
        
        if users_col.find_one({'email': data['email']}):
            flash('Email already registered', 'danger')
            return redirect(url_for('signup'))
        
        # Prepare user data
        hashed_pw = generate_password_hash(data['password'])
        otp = str(random.randint(100000, 999999))
        otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(
            minutes=app.config['OTP_EXPIRY_MINUTES']
        )
        
        location = [0, 0]  # Default location
        if data.get('lng') and data.get('lat'):
            location = [float(data['lng']), float(data['lat'])]
        
        user_data = {
            'name': data['name'],
            'email': data['email'],
            'phone': data['phone'],
            'password': hashed_pw,
            'role': data['role'],
            'blood_group': data.get('blood_group', ''),
            'verified': False,
            'otp': otp,
            'otp_expiry': otp_expiry,
            'location': {
                'type': 'Point',
                'coordinates': location
            },
            'banned': False,
            'created_at': datetime.datetime.utcnow()
        }
        
        # Insert user and send OTP via email only
        users_col.insert_one(user_data)
        send_email(data['email'], 'BloodConnect OTP', f'Your verification OTP is: {otp}')
        
        flash('Verification OTP sent to your email', 'success')
        return redirect(url_for('verify_otp', email=data['email']))
    
    return render_template('signup.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email')
    if not email:
        return redirect(url_for('signup'))
    
    if request.method == 'POST':
        otp = request.form.get('otp', '')
        user = users_col.find_one({'email': email})
        
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('signup'))
        
        if datetime.datetime.utcnow() > user['otp_expiry']:
            flash('OTP expired. Please request a new one.', 'danger')
            return redirect(url_for('resend_otp', email=email))
        
        if otp == user['otp']:
            # Update user and log in
            users_col.update_one(
                {'_id': user['_id']},
                {'$set': {'verified': True}, '$unset': {'otp': '', 'otp_expiry': ''}}
            )
            login_user(User(user))
            flash('Account verified successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid OTP. Please try again.', 'danger')
    
    return render_template('verify_otp.html', email=email)

@app.route('/resend-otp/<email>')
def resend_otp(email):
    user = users_col.find_one({'email': email})
    if user:
        otp = str(random.randint(100000, 999999))
        otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(
            minutes=app.config['OTP_EXPIRY_MINUTES']
        )
        
        users_col.update_one(
            {'_id': user['_id']},
            {'$set': {'otp': otp, 'otp_expiry': otp_expiry}}
        )
        
        send_email(email, 'New BloodConnect OTP', f'Your new OTP is: {otp}')
        flash('New OTP sent successfully', 'success')
        return redirect(url_for('verify_otp', email=email))
    
    flash('User not found', 'danger')
    return redirect(url_for('signup'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users_col.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):
            if not user['verified']:
                flash('Please verify your account first', 'warning')
                return redirect(url_for('verify_otp', email=email))
            if user['banned']:
                flash('Account is suspended. Contact support.', 'danger')
                return redirect(url_for('login'))
            
            login_user(User(user))
            return redirect(url_for('dashboard'))
        
        flash('Invalid email or password', 'danger')
    return render_template('login.html')

# Password reset routes
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users_col.find_one({'email': email})
        
        if user:
            # Generate reset token
            reset_token = str(ObjectId())
            reset_expires = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            
            users_col.update_one(
                {'_id': user['_id']},
                {'$set': {
                    'reset_token': reset_token,
                    'reset_expires': reset_expires
                }}
            )
            
            # Send reset email
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            send_email(
                email,
                'Password Reset Request',
                f'Click the link to reset your password: {reset_link}'
            )
        
        flash('If your email is registered, you will receive a password reset link', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = users_col.find_one({'reset_token': token})
    
    if not user or datetime.datetime.utcnow() > user['reset_expires']:
        flash('Invalid or expired token', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(request.url)
        
        # Update password and clear token
        users_col.update_one(
            {'_id': user['_id']},
            {'$set': {'password': generate_password_hash(password)},
             '$unset': {'reset_token': '', 'reset_expires': ''}}
        )
        
        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    role = current_user.data['role']
    if role == 'donor':
        return render_template('donor_dashboard.html')
    elif role == 'organization':
        return render_template('org_dashboard.html')
    elif role == 'hospital':
        return render_template('hospital_dashboard.html')
    elif role == 'admin':
        return admin_panel()
    return redirect(url_for('index'))

@app.route('/request-blood', methods=['POST'])
@login_required
@role_required(['organization', 'hospital'])
def request_blood():
    data = request.form
    request_data = {
        'requester_id': current_user.get_id(),
        'requester_name': current_user.data['name'],
        'blood_group': data['blood_group'],
        'units': int(data['units']),
        'urgency': data['urgency'],
        'location': {
            'type': 'Point',
            'coordinates': [float(data['lng']), float(data['lat'])]
        },
        'status': 'pending',
        'created_at': datetime.datetime.utcnow(),
        'notes': data.get('notes', '')
    }
    
    # Insert blood request
    request_id = requests_col.insert_one(request_data).inserted_id
    
    # Find matching donors
    donors = users_col.find({
        'role': 'donor',
        'blood_group': data['blood_group'],
        'verified': True,
        'banned': False,
        'location': {
            '$near': {
                '$geometry': {
                    'type': 'Point',
                    'coordinates': [float(data['lng']), float(data['lat'])]
                },
                '$maxDistance': 50 * 1000  # 50km radius
            }
        }
    })
    
    # Notify matching donors via email only
    for donor in donors:
        donor_lng, donor_lat = donor['location']['coordinates']
        distance = haversine(
            float(data['lat']), float(data['lng']),
            donor_lat, donor_lng
        )
        
        message = (f"Urgent blood request for {data['blood_group']} "
                  f"just {round(distance,1)}km from you. "
                  f"Contact: {current_user.data['phone']}")
        
        send_email(donor['email'], 'Blood Request Alert', message)
    
    flash('Blood request created successfully! Donors have been notified via email.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/emergency-alert', methods=['POST'])
@login_required
@role_required(['admin', 'hospital'])
def emergency_alert():
    data = request.form
    blood_group = data['blood_group']
    lat = float(data['lat'])
    lng = float(data['lng'])
    radius = float(data['radius'])  # in km
    
    # Find donors in the area
    donors = users_col.find({
        'role': 'donor',
        'blood_group': blood_group,
        'verified': True,
        'banned': False,
        'location': {
            '$near': {
                '$geometry': {
                    'type': 'Point',
                    'coordinates': [lng, lat]
                },
                '$maxDistance': radius * 1000
            }
        }
    })
    
    # Send emergency alerts via email only
    for donor in donors:
        donor_lng, donor_lat = donor['location']['coordinates']
        distance = haversine(lat, lng, donor_lat, donor_lng)
        
        message = (f"EMERGENCY: {blood_group} blood needed "
                  f"within {radius}km of your location. "
                  f"You're {round(distance,1)}km away. "
                  "Please respond immediately if available.")
        
        send_email(donor['email'], 'EMERGENCY Blood Alert', message)
    
    flash(f'Emergency alert sent to {donors.count()} donors via email', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin-panel')
@login_required
@role_required(['admin'])
def admin_panel():
    # System metrics
    metrics = {
        'donors': users_col.count_documents({'role': 'donor', 'banned': False}),
        'organizations': users_col.count_documents({'role': 'organization', 'banned': False}),
        'hospitals': users_col.count_documents({'role': 'hospital', 'banned': False}),
        'pending_requests': requests_col.count_documents({'status': 'pending'}),
        'completed_requests': requests_col.count_documents({'status': 'completed'}),
        'spam_count': spam_queue_col.count_documents({'status': 'pending'}),
        'banned_users': users_col.count_documents({'banned': True})
    }
    
    # Spam queue items
    spam_items = list(spam_queue_col.find().limit(10))
    
    return render_template('admin_panel.html', metrics=metrics, spam_items=spam_items)

# Spam management routes
@app.route('/spam-queue')
@login_required
@role_required(['admin'])
def spam_queue():
    spam_items = list(spam_queue_col.find({'status': 'pending'}))
    return render_template('spam_queue.html', spam_items=spam_items)

@app.route('/approve-spam/<spam_id>')
@login_required
@role_required(['admin'])
def approve_spam(spam_id):
    spam_queue_col.update_one(
        {'_id': ObjectId(spam_id)},
        {'$set': {'status': 'approved', 'action_by': current_user.get_id()}}
    )
    flash('Spam report approved', 'success')
    return redirect(url_for('spam_queue'))

@app.route('/reject-spam/<spam_id>')
@login_required
@role_required(['admin'])
def reject_spam(spam_id):
    spam_queue_col.update_one(
        {'_id': ObjectId(spam_id)},
        {'$set': {'status': 'rejected', 'action_by': current_user.get_id()}}
    )
    flash('Spam report rejected', 'success')
    return redirect(url_for('spam_queue'))

@app.route('/toggle-ban/<user_id>')
@login_required
@role_required(['admin'])
def toggle_ban(user_id):
    user = users_col.find_one({'_id': ObjectId(user_id)})
    new_status = not user.get('banned', False)
    
    users_col.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'banned': new_status}}
    )
    
    action = "banned" if new_status else "unbanned"
    flash(f'User {action} successfully', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/send-global-alert', methods=['POST'])
@login_required
@role_required(['admin'])
def send_global_alert():
    target_role = request.form.get('target_role', 'all')
    message = request.form['message']
    
    query = {}
    if target_role != 'all':
        query['role'] = target_role
    
    users = users_col.find(query)
    
    for user in users:
        send_email(user['email'], 'BloodConnect Global Alert', message)
    
    # Record alert in database
    alerts_col.insert_one({
        'sent_by': current_user.get_id(),
        'target_role': target_role,
        'message': message,
        'sent_at': datetime.datetime.utcnow()
    })
    
    flash(f'Global alert sent to {users.count()} users via email', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/export-report/<user_id>')
@login_required
def export_report(user_id):
    user = users_col.find_one({'_id': ObjectId(user_id)})
    if not user:
        abort(404)
    
    # Get user's donation/request history
    if user['role'] == 'donor':
        history = list(requests_col.find({'donor_id': user_id}))
    else:
        history = list(requests_col.find({'requester_id': user_id}))
    
    # Generate PDF
    filename = f"bloodconnect_report_{user_id}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    
    content = []
    content.append(Paragraph(f"BloodConnect Report: {user['name']}", styles['Title']))
    content.append(Spacer(1, 12))
    
    content.append(Paragraph(f"User Role: {user['role'].title()}", styles['Heading2']))
    content.append(Paragraph(f"Email: {user['email']}", styles['Normal']))
    content.append(Paragraph(f"Phone: {user['phone']}", styles['Normal']))
    content.append(Spacer(1, 24))
    
    if history:
        content.append(Paragraph("Activity History:", styles['Heading2']))
        for item in history:
            content.append(Paragraph(f"- {item['blood_group']} ({item['units']} units) on "
                                    f"{item['created_at'].strftime('%Y-%m-%d')}", 
                                    styles['Normal']))
            content.append(Spacer(1, 6))
    else:
        content.append(Paragraph("No activity history found", styles['Normal']))
    
    doc.build(content)
    
    return send_file(filename, as_attachment=True)

# Error handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/mobile-login', methods=['GET', 'POST'])
def mobile_login():
    # your phone-only signup logic here
    return render_template('mobile_login.html')
# Add these new routes to app.py

# API endpoint to get donor profile
@app.route('/api/donor/profile')
@login_required
def donor_profile():
    donor = users_col.find_one({'_id': ObjectId(current_user.get_id())})
    if not donor:
        return jsonify({"error": "Donor not found"}), 404
    
    # Calculate next eligible date
    last_donation_date = donor.get('last_donation')
    next_eligible = None
    if last_donation_date:
        next_eligible = last_donation_date + datetime.timedelta(days=90)
    
    return jsonify({
        "name": donor['name'],
        "blood_group": donor.get('blood_group', ''),
        "last_donation": donor.get('last_donation', ''),
        "next_eligible": next_eligible,
        "email": donor['email'],
        "phone": donor['phone']
    })

# API endpoint to get donation history
@app.route('/api/donor/history')
@login_required
def donation_history():
    history = list(requests_col.find({
        'donor_id': current_user.get_id(),
        'status': 'completed'
    }).sort('created_at', -1))
    
    return jsonify([
        {
            "id": str(item['_id']),
            "date": item['created_at'].strftime('%Y-%m-%d'),
            "location": item.get('location_name', 'Unknown Location'),
            "units": item['units'],
            "next_eligible": (item['created_at'] + datetime.timedelta(days=90)).strftime('%Y-%m-%d'),
            "status": "eligible" if (
                datetime.datetime.utcnow() > item['created_at'] + datetime.timedelta(days=90)
            ) else "waiting"
        } for item in history
    ])

# API endpoint to get urgent requests
@app.route('/api/urgent-requests')
@login_required
def urgent_requests():
    # Get requests for the donor's blood type within 50km
    donor = users_col.find_one({'_id': ObjectId(current_user.get_id())})
    if not donor or 'blood_group' not in donor:
        return jsonify([])
    
    requests = list(requests_col.find({
        'blood_group': donor['blood_group'],
        'status': 'pending',
        'created_at': {'$gt': datetime.datetime.utcnow() - datetime.timedelta(hours=24)},
        'location': {
            '$near': {
                '$geometry': {
                    'type': 'Point',
                    'coordinates': donor['location']['coordinates']
                },
                '$maxDistance': 50000  # 50km
            }
        }
    }).sort('urgency', -1).limit(10))
    
    return jsonify([
        {
            "id": str(item['_id']),
            "title": f"Urgent Need for {item['blood_group']}",
            "message": f"{item['requester_name']} needs {item['units']} units of blood. "
                      f"Urgency: {item['urgency']}",
            "created_at": item['created_at'].isoformat(),
            "requester_phone": item.get('requester_phone', '')
        } for item in requests
    ])

# API endpoint to get upcoming camps
@app.route('/api/upcoming-camps')
@login_required
def upcoming_camps():
    # Get camps within 100km in the next 30 days
    donor = users_col.find_one({'_id': ObjectId(current_user.get_id())})
    
    camps = list(db.camps.find({
        'date': {'$gt': datetime.datetime.utcnow()},
        'location': {
            '$near': {
                '$geometry': {
                    'type': 'Point',
                    'coordinates': donor['location']['coordinates']
                },
                '$maxDistance': 100000  # 100km
            }
        }
    }).sort('date', 1).limit(5))
    
    return jsonify([
        {
            "id": str(item['_id']),
            "name": item['name'],
            "date": item['date'].strftime('%Y-%m-%d'),
            "time": item.get('time', '10:00 AM - 4:00 PM'),
            "location": item['location_name'],
            "address": item['address'],
            "lat": item['location']['coordinates'][1],
            "lng": item['location']['coordinates'][0],
            "registered": current_user.get_id() in item.get('registered_donors', [])
        } for item in camps
    ])

# API endpoint to respond to a request
@app.route('/api/respond-to-request/<request_id>', methods=['POST'])
@login_required
def respond_to_request(request_id):
    request_data = requests_col.find_one({'_id': ObjectId(request_id)})
    if not request_data:
        return jsonify({"error": "Request not found"}), 404
    
    # Send notification to requester
    requester = users_col.find_one({'_id': ObjectId(request_data['requester_id'])})
    if requester:
        message = (f"{current_user.data['name']} has responded to your blood request! "
                  f"Contact them at: {current_user.data['phone']}")
        send_email(requester['email'], 'Donor Response', message)
    
    return jsonify({"message": "Response sent successfully"})

# API endpoint to register for a camp
@app.route('/api/register-for-camp/<camp_id>', methods=['POST'])
@login_required
def register_for_camp(camp_id):
    result = db.camps.update_one(
        {'_id': ObjectId(camp_id)},
        {'$addToSet': {'registered_donors': current_user.get_id()}}
    )
    
    if result.modified_count == 0:
        return jsonify({"error": "Registration failed"}), 400
    
    return jsonify({"message": "Registered successfully"})
# Add this near your other collection definitions
events_col = db.events

# Add these new routes after your existing routes

# GET /api/events - Get all events sorted by date
@app.route('/api/events', methods=['GET'])
@login_required
def get_events():
    """Return all events sorted by date in ascending order"""
    events = list(events_col.find().sort('date', 1))
    for event in events:
        event['_id'] = str(event['_id'])  # Convert ObjectId to string
    return jsonify(events)

# POST /api/events - Create a new event
@app.route('/api/events', methods=['POST'])
@login_required
@role_required(['organization', 'admin'])
def create_event():
    """Create a new event with auto-generated stats fields"""
    data = request.json
    # Validate required fields
    if not all(key in data for key in ['title', 'date', 'startTime', 'endTime', 'location', 'description']):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Create event document with auto-generated stats
    event_doc = {
        'title': data['title'],
        'date': datetime.datetime.strptime(data['date'], '%Y-%m-%d'),
        'startTime': data['startTime'],
        'endTime': data['endTime'],
        'location': data['location'],
        'description': data['description'],
        'registered': 0,  # Auto-initialized
        'donated': 0,     # Auto-initialized
        'units': int(data.get('units', 0)),  # Default to 0 if not provided
        'progress': 0,    # Auto-initialized
        'created_by': current_user.get_id(),
        'created_at': datetime.datetime.utcnow(),
        'status': 'active'
    }
    
    # Insert into MongoDB
    result = events_col.insert_one(event_doc)
    event_doc['_id'] = str(result.inserted_id)  # Add string ID for response
    return jsonify(event_doc), 201

# PUT /api/events/<event_id> - Update an event
@app.route('/api/events/<event_id>', methods=['PUT'])
@login_required
@role_required(['organization', 'admin'])
def update_event(event_id):
    """Update event details and optionally stats"""
    data = request.json
    update_data = {}
    
    # Allowed update fields
    for field in ['title', 'date', 'startTime', 'endTime', 'location', 'description',
                  'registered', 'donated', 'units', 'progress']:
        if field in data:
            if field == 'date':
                update_data[field] = datetime.datetime.strptime(data['date'], '%Y-%m-%d')
            else:
                update_data[field] = data[field]
    
    # Update event in MongoDB
    result = events_col.update_one(
        {'_id': ObjectId(event_id)},
        {'$set': update_data}
    )
    
    if result.matched_count == 0:
        return jsonify({"error": "Event not found"}), 404
    
    # Return updated event
    updated_event = events_col.find_one({'_id': ObjectId(event_id)})
    updated_event['_id'] = str(updated_event['_id'])
    return jsonify(updated_event)

# DELETE /api/events/<event_id> - Mark event as closed
@app.route('/api/events/<event_id>', methods=['DELETE'])
@login_required
@role_required(['organization', 'admin'])
def close_event(event_id):
    """Mark an event as closed (soft delete)"""
    result = events_col.update_one(
        {'_id': ObjectId(event_id)},
        {'$set': {'status': 'closed'}}
    )
    
    if result.matched_count == 0:
        return jsonify({"error": "Event not found"}), 404
    
    return jsonify({"message": "Event marked as closed"})
@app.route('/api/hospital/active-requests')
@login_required
def active_requests():
    """Get all open blood requests"""
    # Query for open requests (status: open or urgent)
    requests = list(requests_col.find({
        "hospital_id": current_user.id,
        "status": {"$in": ["open", "urgent"]}
    }))
    
    # Convert to JSON-safe format
    for req in requests:
        req['id'] = str(req['_id'])
        req['date'] = req['date'].isoformat()
        req['requiredDate'] = req['requiredDate'].isoformat()
        del req['_id']
    
    return jsonify(requests), 200

@app.route('/api/hospital/history')
@login_required
def request_history():
    """Get fulfilled request history"""
    # Query for fulfilled requests
    requests = list(requests_col.find({
        "hospital_id": current_user.id,
        "status": "fulfilled"
    }))
    
    # Convert to JSON-safe format
    for req in requests:
        req['id'] = str(req['_id'])
        req['date'] = req['date'].isoformat()
        req['fulfilledDate'] = req['fulfilledDate'].isoformat()
        del req['_id']
    
    return jsonify(requests), 200

@app.route('/api/hospital/inventory')
@login_required
def inventory_count():
    """Get current inventory count"""
    # Get inventory from stats collection
    inventory = stats_col.find_one({"hospital_id": current_user.id})
    return jsonify({"inventory": inventory["count"]}), 200

@app.route('/api/search-donors')
@login_required
def search_donors():
    """Search donors by blood group and location"""
    blood_group = request.args.get('blood_group')
    radius = int(request.args.get('radius', 10))
    
    # Get hospital location from current user
    hospital = users_col.find_one({"_id": current_user.id})
    hospital_loc = hospital['location']
    
    # Geospatial query
    donors = list(users_col.find({
        "blood_group": blood_group,
        "location": {
            "$near": {
                "$geometry": hospital_loc,
                "$maxDistance": radius * 1000  # Convert km to meters
            }
        }
    }))
    
    # Format results
    results = []
    for donor in donors:
        results.append({
            "id": str(donor['_id']),
            "name": donor['name'],
            "distance": donor['distance']  # Assume distance is calculated in query
        })
    
    return jsonify(results), 200

@app.route('/api/hospital/requests', methods=['POST'])
@login_required
def create_request():
    """Create new blood request"""
    data = request.json
    
    # Validate required fields
    required = ['patientName', 'patientAge', 'bloodGroup', 'units', 'requiredDate', 'urgency']
    if not all(field in data for field in required):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Create request document
    new_request = {
        "hospital_id": current_user.id,
        "patientName": data['patientName'],
        "patientAge": int(data['patientAge']),
        "bloodGroup": data['bloodGroup'],
        "units": int(data['units']),
        "status": "open",
        "date": datetime.utcnow(),
        "requiredDate": datetime.fromisoformat(data['requiredDate']),
        "urgency": data['urgency'],
        "location": data.get('location', ''),
        "notes": data.get('notes', '')
    }
    
    # Insert into database
    result = requests_col.insert_one(new_request)
    new_request['id'] = str(result.inserted_id)
    
    # Decrement inventory
    stats_col.update_one(
        {"hospital_id": current_user.id},
        {"$inc": {"count": -int(data['units'])}}
    )
    
    # Format dates for response
    new_request['date'] = new_request['date'].isoformat()
    new_request['requiredDate'] = new_request['requiredDate'].isoformat()
    del new_request['_id']
    
    return jsonify(new_request), 201

@app.route('/api/hospital/requests/<id>/fulfill', methods=['POST'])
@login_required
def fulfill_request(id):
    """Mark request as fulfilled"""
    # Validate ID format
    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid ID format"}), 400
    
    # Find and update request
    result = requests_col.update_one(
        {"_id": ObjectId(id), "hospital_id": current_user.id},
        {
            "$set": {
                "status": "fulfilled",
                "fulfilledDate": datetime.utcnow()
            }
        }
    )
    
    if result.modified_count == 0:
        return jsonify({"error": "Request not found"}), 404
    
    # Get units to increment inventory
    request_data = requests_col.find_one({"_id": ObjectId(id)})
    units = request_data['units']
    
    # Increment inventory
    stats_col.update_one(
        {"hospital_id": current_user.id},
        {"$inc": {"count": units}}
    )
    
    return jsonify({"success": True}), 200

@app.route('/api/hospital/requests/<id>', methods=['DELETE'])
@login_required
def delete_request(id):
    """Delete a blood request"""
    # Validate ID format
    if not ObjectId.is_valid(id):
        return jsonify({"error": "Invalid ID format"}), 400
    
    # Delete request
    result = requests_col.delete_one({
        "_id": ObjectId(id),
        "hospital_id": current_user.id
    })
    
    if result.deleted_count == 0:
        return jsonify({"error": "Request not found"}), 404
    
    return jsonify({"success": True}), 200

if __name__ == '__main__':
    app.run(debug=True)
