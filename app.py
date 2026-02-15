from flask import Flask, jsonify, send_file, render_template, request, redirect, url_for, session, flash
from flask_compress import Compress
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import jwt
import secrets
import os
from functools import wraps
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['COMPRESS_MIMETYPES'] = ['text/html', 'text/css', 'text/xml', 'application/json', 'application/javascript']
app.config['COMPRESS_LEVEL'] = 6
app.config['COMPRESS_MIN_SIZE'] = 500

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@veggo.com')

# MongoDB configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client['veggo_db']

# Collections
users_col = db['users']
admins_col = db['admins']
suppliers_col = db['suppliers']
agents_col = db['agents']
products_col = db['products']
orders_col = db['orders']
addresses_col = db['addresses']
bills_col = db['bills']
email_tokens_col = db['email_tokens']

# Initialize extensions
Compress(app)
CORS(app)
mail = Mail(app)

# JWT Configuration
JWT_SECRET = os.getenv('JWT_SECRET', secrets.token_hex(32))
JWT_EXPIRY = timedelta(hours=24)

# ==================== AUTHENTICATION DECORATORS ====================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            current_user = users_col.find_one({'_id': ObjectId(data['user_id'])})
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
                
            if not current_user.get('verified'):
                return jsonify({'error': 'Email not verified'}), 403
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'ADMIN':
            flash('Admin access required', 'error')
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated

def agent_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'DELIVERY_AGENT':
            flash('Agent access required', 'error')
            return redirect(url_for('agent.login'))
        return f(*args, **kwargs)
    return decorated

# ==================== EMAIL FUNCTIONS ====================

def send_verification_email(email, token):
    """Send email verification link"""
    verification_url = f"{os.getenv('BASE_URL', 'http://localhost:5000')}/verify-email?token={token}"
    
    msg = Message('Verify Your VEGGO Account', recipients=[email])
    msg.body = f'''Hello!

Thank you for signing up with VEGGO.

Please verify your email address by clicking the link below:
{verification_url}

This link will expire in 24 hours.

Best regards,
VEGGO Team
'''
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_agent_verification_email(email, token):
    """Send agent verification email"""
    verification_url = f"{os.getenv('BASE_URL', 'http://localhost:5000')}/verify-agent?token={token}"
    
    msg = Message('Verify Your VEGGO Agent Account', recipients=[email])
    msg.body = f'''Hello!

Thank you for registering as a delivery agent with VEGGO.

Please verify your email address by clicking the link below:
{verification_url}

After email verification, your account will be reviewed by our admin team for approval.

This link will expire in 24 hours.

Best regards,
VEGGO Team
'''
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_agent_approval_email(email, agent_name):
    """Send agent approval notification"""
    msg = Message('Your VEGGO Agent Account has been Approved!', recipients=[email])
    msg.body = f'''Hello {agent_name}!

Great news! Your delivery agent account has been approved by our admin team.

You can now login and start accepting delivery orders:
{os.getenv('BASE_URL', 'http://localhost:5000')}/agent/login

Thank you for joining the VEGGO delivery team!

Best regards,
VEGGO Team
'''
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_password_reset_email(email, token):
    """Send password reset link"""
    reset_url = f"{os.getenv('BASE_URL', 'http://localhost:5000')}/reset-password?token={token}"
    
    msg = Message('Reset Your VEGGO Password', recipients=[email])
    msg.body = f'''Hello!

You requested to reset your password.

Click the link below to reset your password:
{reset_url}

This link will expire in 15 minutes.

If you didn't request this, please ignore this email.

Best regards,
VEGGO Team
'''
    
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_order_notification(email, order_id, status):
    """Send order status notification"""
    status_messages = {
        'placed': 'Your order has been placed successfully!',
        'confirmed': 'Your order has been confirmed.',
        'packed': 'Your order is being packed.',
        'assigned_to_agent': 'Your order has been assigned to a delivery agent.',
        'out_for_delivery': 'Your order is out for delivery!',
        'delivered': 'Your order has been delivered. Thank you for shopping with VEGGO!'
    }
    
    msg = Message(f'VEGGO Order Update - {order_id}', recipients=[email])
    msg.body = f'''Hello!

{status_messages.get(status, 'Order status updated.')}

Order ID: {order_id}
Status: {status}

You can track your order at: {os.getenv('BASE_URL', 'http://localhost:5000')}/orders/{order_id}

Best regards,
VEGGO Team
'''
    
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Email error: {e}")

# ==================== API ENDPOINTS ====================

@app.route('/')
def index():
    return jsonify({
        'message': 'Welcome to VEGGO API',
        'version': '1.0.0',
        'endpoints': {
            'api': '/api/v1',
            'admin_panel': '/admin',
            'agent_panel': '/agent'
        }
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

# ==================== USER AUTHENTICATION API ====================

@app.route('/api/v1/auth/signup', methods=['POST'])
def signup():
    """User signup with email verification"""
    data = request.json
    
    # Validate required fields
    required = ['username', 'email', 'phone', 'password']
    if not all(field in data for field in required):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user exists
    if users_col.find_one({'email': data['email']}):
        return jsonify({'error': 'Email already registered'}), 400
    
    if users_col.find_one({'username': data['username']}):
        return jsonify({'error': 'Username already taken'}), 400
    
    # Create user
    user = {
        'username': data['username'],
        'email': data['email'],
        'phone': data['phone'],
        'password': generate_password_hash(data['password']),
        'role': 'USER',
        'verified': False,
        'created_at': datetime.utcnow()
    }
    
    result = users_col.insert_one(user)
    
    # Generate verification token
    token = secrets.token_urlsafe(32)
    email_tokens_col.insert_one({
        'user_id': result.inserted_id,
        'token': token,
        'type': 'verification',
        'expires_at': datetime.utcnow() + timedelta(hours=24)
    })
    
    # Send verification email
    send_verification_email(data['email'], token)
    
    return jsonify({
        'message': 'Signup successful. Please check your email to verify your account.',
        'user_id': str(result.inserted_id)
    }), 201

@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    """User login"""
    data = request.json
    
    if not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400
    
    user = users_col.find_one({'email': data['email']})
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not check_password_hash(user['password'], data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.get('verified'):
        return jsonify({'error': 'Please verify your email before logging in'}), 403
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': str(user['_id']),
        'role': user['role'],
        'exp': datetime.utcnow() + JWT_EXPIRY
    }, JWT_SECRET, algorithm='HS256')
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'id': str(user['_id']),
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        }
    })

@app.route('/verify-email')
def verify_email():
    """Verify email address"""
    token = request.args.get('token')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    token_doc = email_tokens_col.find_one({
        'token': token,
        'type': 'verification'
    })
    
    if not token_doc:
        return jsonify({'error': 'Invalid token'}), 400
    
    if datetime.utcnow() > token_doc['expires_at']:
        return jsonify({'error': 'Token expired'}), 400
    
    # Verify user
    users_col.update_one(
        {'_id': token_doc['user_id']},
        {'$set': {'verified': True}}
    )
    
    # Delete token
    email_tokens_col.delete_one({'_id': token_doc['_id']})
    
    return jsonify({'message': 'Email verified successfully. You can now login.'})

@app.route('/verify-agent')
def verify_agent():
    """Verify agent email address"""
    token = request.args.get('token')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    token_doc = email_tokens_col.find_one({
        'token': token,
        'type': 'agent_verification'
    })
    
    if not token_doc:
        return jsonify({'error': 'Invalid token'}), 400
    
    if datetime.utcnow() > token_doc['expires_at']:
        return jsonify({'error': 'Token expired'}), 400
    
    # Verify agent
    agents_col.update_one(
        {'_id': token_doc['agent_id']},
        {'$set': {'verified': True}}
    )
    
    # Delete token
    email_tokens_col.delete_one({'_id': token_doc['_id']})
    
    return jsonify({'message': 'Email verified successfully. Your account is now pending admin approval.'})

@app.route('/api/v1/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Request password reset"""
    data = request.json
    
    if not data.get('email'):
        return jsonify({'error': 'Email required'}), 400
    
    user = users_col.find_one({'email': data['email']})
    
    if not user:
        # Don't reveal if email exists
        return jsonify({'message': 'If email exists, reset link has been sent.'})
    
    # Generate reset token
    token = secrets.token_urlsafe(32)
    email_tokens_col.insert_one({
        'user_id': user['_id'],
        'token': token,
        'type': 'password_reset',
        'expires_at': datetime.utcnow() + timedelta(minutes=15)
    })
    
    # Send reset email
    send_password_reset_email(data['email'], token)
    
    return jsonify({'message': 'If email exists, reset link has been sent.'})

@app.route('/api/v1/auth/reset-password', methods=['POST'])
def reset_password():
    """Reset password with token"""
    data = request.json
    
    if not data.get('token') or not data.get('password'):
        return jsonify({'error': 'Token and new password required'}), 400
    
    token_doc = email_tokens_col.find_one({
        'token': data['token'],
        'type': 'password_reset'
    })
    
    if not token_doc:
        return jsonify({'error': 'Invalid token'}), 400
    
    if datetime.utcnow() > token_doc['expires_at']:
        return jsonify({'error': 'Token expired'}), 400
    
    # Update password
    users_col.update_one(
        {'_id': token_doc['user_id']},
        {'$set': {'password': generate_password_hash(data['password'])}}
    )
    
    # Delete token
    email_tokens_col.delete_one({'_id': token_doc['_id']})
    
    return jsonify({'message': 'Password reset successful'})

# ==================== PRODUCT API ====================

@app.route('/api/v1/products', methods=['GET'])
def get_products():
    """Get all products"""
    products = list(products_col.find())
    
    for product in products:
        product['_id'] = str(product['_id'])
        if 'supplier_id' in product:
            product['supplier_id'] = str(product['supplier_id'])
    
    return jsonify(products)

@app.route('/api/v1/products/<product_id>', methods=['GET'])
def get_product(product_id):
    """Get single product"""
    try:
        product = products_col.find_one({'_id': ObjectId(product_id)})
        
        if not product:
            return jsonify({'error': 'Product not found'}), 404
        
        product['_id'] = str(product['_id'])
        if 'supplier_id' in product:
            product['supplier_id'] = str(product['supplier_id'])
        
        return jsonify(product)
    except:
        return jsonify({'error': 'Invalid product ID'}), 400

# ==================== ORDER API ====================

@app.route('/api/v1/orders', methods=['POST'])
@token_required
def create_order(current_user):
    """Create new order"""
    data = request.json
    
    required = ['items', 'address_id']
    if not all(field in data for field in required):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Calculate totals
    subtotal = 0
    items = []
    
    for item in data['items']:
        product = products_col.find_one({'_id': ObjectId(item['product_id'])})
        
        if not product:
            return jsonify({'error': f"Product {item['product_id']} not found"}), 400
        
        if product['stock'] < item['quantity']:
            return jsonify({'error': f"Insufficient stock for {product['name']}"}), 400
        
        item_price = product.get('discount_price', product['price'])
        item_total = item_price * item['quantity']
        subtotal += item_total
        
        items.append({
            'product_id': ObjectId(item['product_id']),
            'name': product['name'],
            'quantity': item['quantity'],
            'price': item_price,
            'total': item_total
        })
        
        # Update stock
        products_col.update_one(
            {'_id': ObjectId(item['product_id'])},
            {'$inc': {'stock': -item['quantity']}}
        )
    
    delivery_charge = 50  # Fixed delivery charge
    total = subtotal + delivery_charge
    
    # Create order
    order = {
        'user_id': current_user['_id'],
        'items': items,
        'address_id': ObjectId(data['address_id']),
        'subtotal': subtotal,
        'delivery_charge': delivery_charge,
        'total': total,
        'status': 'pending',
        'created_at': datetime.utcnow()
    }
    
    result = orders_col.insert_one(order)
    
    # Send order confirmation email
    send_order_notification(current_user['email'], str(result.inserted_id), 'placed')
    
    return jsonify({
        'message': 'Order placed successfully',
        'order_id': str(result.inserted_id),
        'total': total
    }), 201

@app.route('/api/v1/orders', methods=['GET'])
@token_required
def get_user_orders(current_user):
    """Get user's order history"""
    orders = list(orders_col.find({'user_id': current_user['_id']}).sort('created_at', -1))
    
    for order in orders:
        order['_id'] = str(order['_id'])
        order['user_id'] = str(order['user_id'])
        order['address_id'] = str(order['address_id'])
        
        for item in order['items']:
            item['product_id'] = str(item['product_id'])
    
    return jsonify(orders)

@app.route('/api/v1/orders/<order_id>', methods=['GET'])
@token_required
def get_order(current_user, order_id):
    """Get specific order"""
    try:
        order = orders_col.find_one({
            '_id': ObjectId(order_id),
            'user_id': current_user['_id']
        })
        
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        order['_id'] = str(order['_id'])
        order['user_id'] = str(order['user_id'])
        order['address_id'] = str(order['address_id'])
        
        for item in order['items']:
            item['product_id'] = str(item['product_id'])
        
        return jsonify(order)
    except:
        return jsonify({'error': 'Invalid order ID'}), 400

# ==================== ADDRESS API ====================

@app.route('/api/v1/addresses', methods=['POST'])
@token_required
def add_address(current_user):
    """Add new address"""
    data = request.json
    
    required = ['label', 'street', 'city', 'postal_code']
    if not all(field in data for field in required):
        return jsonify({'error': 'Missing required fields'}), 400
    
    address = {
        'user_id': current_user['_id'],
        'label': data['label'],
        'street': data['street'],
        'city': data['city'],
        'postal_code': data['postal_code'],
        'is_default': data.get('is_default', False),
        'created_at': datetime.utcnow()
    }
    
    # If this is default, unset other defaults
    if address['is_default']:
        addresses_col.update_many(
            {'user_id': current_user['_id']},
            {'$set': {'is_default': False}}
        )
    
    result = addresses_col.insert_one(address)
    
    return jsonify({
        'message': 'Address added successfully',
        'address_id': str(result.inserted_id)
    }), 201

@app.route('/api/v1/addresses', methods=['GET'])
@token_required
def get_addresses(current_user):
    """Get user's addresses"""
    addresses = list(addresses_col.find({'user_id': current_user['_id']}))
    
    for address in addresses:
        address['_id'] = str(address['_id'])
        address['user_id'] = str(address['user_id'])
    
    return jsonify(addresses)

@app.route('/api/v1/addresses/<address_id>', methods=['PUT'])
@token_required
def update_address(current_user, address_id):
    """Update address"""
    data = request.json
    
    try:
        result = addresses_col.update_one(
            {'_id': ObjectId(address_id), 'user_id': current_user['_id']},
            {'$set': data}
        )
        
        if result.matched_count == 0:
            return jsonify({'error': 'Address not found'}), 404
        
        return jsonify({'message': 'Address updated successfully'})
    except:
        return jsonify({'error': 'Invalid address ID'}), 400

@app.route('/api/v1/addresses/<address_id>', methods=['DELETE'])
@token_required
def delete_address(current_user, address_id):
    """Delete address"""
    try:
        result = addresses_col.delete_one({
            '_id': ObjectId(address_id),
            'user_id': current_user['_id']
        })
        
        if result.deleted_count == 0:
            return jsonify({'error': 'Address not found'}), 404
        
        return jsonify({'message': 'Address deleted successfully'})
    except:
        return jsonify({'error': 'Invalid address ID'}), 400

# ==================== BILL GENERATION ====================

def generate_bill_pdf(order_id):
    """Generate PDF bill for order"""
    order = orders_col.find_one({'_id': ObjectId(order_id)})
    
    if not order:
        return None
    
    user = users_col.find_one({'_id': order['user_id']})
    address = addresses_col.find_one({'_id': order['address_id']})
    
    # Create PDF
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    # Header
    p.setFont("Helvetica-Bold", 24)
    p.drawString(100, 750, "VEGGO")
    
    p.setFont("Helvetica", 12)
    p.drawString(100, 730, f"Invoice #: {order_id}")
    p.drawString(100, 715, f"Date: {order['created_at'].strftime('%Y-%m-%d %H:%M')}")
    
    # Customer info
    p.drawString(100, 690, f"Customer: {user['username']}")
    p.drawString(100, 675, f"Phone: {user['phone']}")
    p.drawString(100, 660, f"Email: {user['email']}")
    p.drawString(100, 645, f"Address: {address['street']}, {address['city']}")
    
    # Items table
    y = 610
    p.setFont("Helvetica-Bold", 12)
    p.drawString(100, y, "Product")
    p.drawString(300, y, "Qty")
    p.drawString(370, y, "Price")
    p.drawString(470, y, "Total")
    
    y -= 20
    p.setFont("Helvetica", 11)
    
    for item in order['items']:
        p.drawString(100, y, item['name'][:30])
        p.drawString(300, y, str(item['quantity']))
        p.drawString(370, y, f"Rs. {item['price']}")
        p.drawString(470, y, f"Rs. {item['total']}")
        y -= 20
    
    # Totals
    y -= 20
    p.drawString(370, y, "Subtotal:")
    p.drawString(470, y, f"Rs. {order['subtotal']}")
    
    y -= 20
    p.drawString(370, y, "Delivery:")
    p.drawString(470, y, f"Rs. {order['delivery_charge']}")
    
    y -= 20
    p.setFont("Helvetica-Bold", 12)
    p.drawString(370, y, "Grand Total:")
    p.drawString(470, y, f"Rs. {order['total']}")
    
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return buffer

@app.route('/api/v1/orders/<order_id>/bill', methods=['GET'])
@token_required
def download_bill(current_user, order_id):
    """Download order bill"""
    try:
        order = orders_col.find_one({
            '_id': ObjectId(order_id),
            'user_id': current_user['_id']
        })
        
        if not order:
            return jsonify({'error': 'Order not found'}), 404
        
        pdf_buffer = generate_bill_pdf(order_id)
        
        if not pdf_buffer:
            return jsonify({'error': 'Could not generate bill'}), 500
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'veggo_invoice_{order_id}.pdf'
        )
    except:
        return jsonify({'error': 'Invalid order ID'}), 400

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('DEBUG', 'False') == 'True')
