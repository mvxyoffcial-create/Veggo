"""Agent panel routes - Server-rendered HTML"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from functools import wraps
import secrets

agent_bp = Blueprint('agent', __name__, url_prefix='/agent')

def agent_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'DELIVERY_AGENT':
            flash('Agent access required', 'error')
            return redirect(url_for('agent.login'))
        return f(*args, **kwargs)
    return decorated

@agent_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Agent login page"""
    if request.method == 'POST':
        from app import agents_col
        
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Email and password are required', 'error')
            return render_template('agent/login.html')
        
        agent = agents_col.find_one({'email': email})
        
        if not agent:
            flash('Invalid credentials', 'error')
            return render_template('agent/login.html')
        
        if not check_password_hash(agent['password'], password):
            flash('Invalid credentials', 'error')
            return render_template('agent/login.html')
        
        if not agent.get('verified', False):
            flash('Please verify your email address first. Check your inbox for verification link.', 'error')
            return render_template('agent/login.html')
        
        if not agent.get('approved', False):
            flash('Your account is pending admin approval. You will receive an email once approved.', 'error')
            return render_template('agent/login.html')
        
        session['user_id'] = str(agent['_id'])
        session['role'] = 'DELIVERY_AGENT'
        session['username'] = agent['name']
        flash('Login successful!', 'success')
        return redirect(url_for('agent.dashboard'))
    
    return render_template('agent/login.html')

@agent_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """Agent signup with email verification"""
    if request.method == 'POST':
        from app import agents_col, email_tokens_col, send_agent_verification_email
        
        # Get form data
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        vehicle_type = request.form.get('vehicle_type', '')
        license_number = request.form.get('license_number', '').strip()
        
        # Validate input
        if not all([name, email, phone, password, vehicle_type, license_number]):
            flash('All fields are required', 'error')
            return render_template('agent/signup.html')
        
        # Check if agent exists
        if agents_col.find_one({'email': email}):
            flash('Email already registered', 'error')
            return render_template('agent/signup.html')
        
        # Create agent
        agent = {
            'name': name,
            'email': email,
            'phone': phone,
            'password': generate_password_hash(password),
            'vehicle_type': vehicle_type,
            'license_number': license_number,
            'verified': False,
            'approved': False,
            'created_at': datetime.utcnow()
        }
        
        result = agents_col.insert_one(agent)
        
        # Generate verification token
        token = secrets.token_urlsafe(32)
        email_tokens_col.insert_one({
            'agent_id': result.inserted_id,
            'token': token,
            'type': 'agent_verification',
            'expires_at': datetime.utcnow() + timedelta(hours=24)
        })
        
        # Send verification email
        send_agent_verification_email(email, token)
        
        flash('Signup successful! Please check your email to verify your account.', 'success')
        return redirect(url_for('agent.login'))
    
    return render_template('agent/signup.html')

@agent_bp.route('/logout')
def logout():
    """Agent logout"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('agent.login'))

@agent_bp.route('/dashboard')
@agent_required
def dashboard():
    """Agent dashboard"""
    from app import orders_col, addresses_col, users_col
    
    agent_id = ObjectId(session['user_id'])
    
    # Get assigned orders
    assigned_orders = list(orders_col.find({
        'agent_id': agent_id,
        'status': {'$in': ['assigned_to_agent', 'out_for_delivery']}
    }).sort('created_at', -1))
    
    # Enrich orders with user and address data
    for order in assigned_orders:
        user = users_col.find_one({'_id': order['user_id']})
        address = addresses_col.find_one({'_id': order['address_id']})
        order['user'] = user
        order['address'] = address
    
    # Get delivery statistics
    stats = {
        'pending': orders_col.count_documents({'agent_id': agent_id, 'status': 'assigned_to_agent'}),
        'in_transit': orders_col.count_documents({'agent_id': agent_id, 'status': 'out_for_delivery'}),
        'completed': orders_col.count_documents({'agent_id': agent_id, 'status': 'delivered'})
    }
    
    return render_template('agent/dashboard.html', orders=assigned_orders, stats=stats)

@agent_bp.route('/orders/<order_id>/accept', methods=['POST'])
@agent_required
def accept_order(order_id):
    """Accept delivery order"""
    from app import orders_col, users_col, send_order_notification
    
    agent_id = ObjectId(session['user_id'])
    
    result = orders_col.update_one(
        {'_id': ObjectId(order_id), 'agent_id': agent_id},
        {'$set': {'status': 'out_for_delivery'}}
    )
    
    if result.matched_count > 0:
        # Send notification
        order = orders_col.find_one({'_id': ObjectId(order_id)})
        user = users_col.find_one({'_id': order['user_id']})
        send_order_notification(user['email'], order_id, 'out_for_delivery')
        
        flash('Order accepted and marked as out for delivery', 'success')
    else:
        flash('Order not found', 'error')
    
    return redirect(url_for('agent.dashboard'))

@agent_bp.route('/orders/<order_id>/deliver', methods=['POST'])
@agent_required
def mark_delivered(order_id):
    """Mark order as delivered"""
    from app import orders_col, users_col, send_order_notification
    
    agent_id = ObjectId(session['user_id'])
    
    result = orders_col.update_one(
        {'_id': ObjectId(order_id), 'agent_id': agent_id},
        {'$set': {
            'status': 'delivered',
            'delivered_at': datetime.utcnow()
        }}
    )
    
    if result.matched_count > 0:
        # Send notification
        order = orders_col.find_one({'_id': ObjectId(order_id)})
        user = users_col.find_one({'_id': order['user_id']})
        send_order_notification(user['email'], order_id, 'delivered')
        
        flash('Order marked as delivered', 'success')
    else:
        flash('Order not found', 'error')
    
    return redirect(url_for('agent.dashboard'))

@agent_bp.route('/history')
@agent_required
def history():
    """View delivery history"""
    from app import orders_col, users_col, addresses_col
    
    agent_id = ObjectId(session['user_id'])
    
    # Get all completed deliveries
    completed_orders = list(orders_col.find({
        'agent_id': agent_id,
        'status': 'delivered'
    }).sort('delivered_at', -1))
    
    # Enrich orders
    for order in completed_orders:
        user = users_col.find_one({'_id': order['user_id']})
        address = addresses_col.find_one({'_id': order['address_id']})
        order['user'] = user
        order['address'] = address
    
    return render_template('agent/history.html', orders=completed_orders)
