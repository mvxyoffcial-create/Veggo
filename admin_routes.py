"""Admin panel routes - Server-rendered HTML"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from bson.objectid import ObjectId
from datetime import datetime
from functools import wraps

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'ADMIN':
            flash('Admin access required', 'error')
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    if request.method == 'POST':
        from app import admins_col
        
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Validate input
        if not email or not password:
            flash('Email and password are required', 'error')
            return render_template('admin/login.html')
        
        # Find admin
        admin = admins_col.find_one({'email': email})
        
        if not admin:
            flash('Invalid credentials', 'error')
            return render_template('admin/login.html')
        
        # Check password
        if check_password_hash(admin['password'], password):
            session['user_id'] = str(admin['_id'])
            session['role'] = 'ADMIN'
            session['username'] = admin['username']
            flash('Login successful!', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('admin/login.html')

@admin_bp.route('/logout')
def logout():
    """Admin logout"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin.login'))

@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    """Admin dashboard"""
    from app import users_col, products_col, orders_col, agents_col
    
    stats = {
        'total_users': users_col.count_documents({}),
        'total_products': products_col.count_documents({}),
        'total_orders': orders_col.count_documents({}),
        'pending_orders': orders_col.count_documents({'status': 'pending'}),
        'total_agents': agents_col.count_documents({}),
        'pending_agents': agents_col.count_documents({'approved': False, 'verified': True})
    }
    
    recent_orders = list(orders_col.find().sort('created_at', -1).limit(10))
    
    return render_template('admin/dashboard.html', stats=stats, recent_orders=recent_orders)

@admin_bp.route('/users')
@admin_required
def users():
    """User management"""
    from app import users_col
    
    all_users = list(users_col.find().sort('created_at', -1))
    
    return render_template('admin/users.html', users=all_users)

@admin_bp.route('/users/<user_id>/block', methods=['POST'])
@admin_required
def block_user(user_id):
    """Block/unblock user"""
    from app import users_col
    
    user = users_col.find_one({'_id': ObjectId(user_id)})
    
    if user:
        new_status = not user.get('blocked', False)
        users_col.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'blocked': new_status}}
        )
        flash(f"User {'blocked' if new_status else 'unblocked'} successfully", 'success')
    else:
        flash('User not found', 'error')
    
    return redirect(url_for('admin.users'))

@admin_bp.route('/users/<user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete user"""
    from app import users_col
    
    result = users_col.delete_one({'_id': ObjectId(user_id)})
    
    if result.deleted_count > 0:
        flash('User deleted successfully', 'success')
    else:
        flash('User not found', 'error')
    
    return redirect(url_for('admin.users'))

@admin_bp.route('/products')
@admin_required
def products():
    """Product management"""
    from app import products_col
    
    all_products = list(products_col.find().sort('created_at', -1))
    
    return render_template('admin/products.html', products=all_products)

@admin_bp.route('/products/add', methods=['GET', 'POST'])
@admin_required
def add_product():
    """Add new product"""
    if request.method == 'POST':
        from app import products_col
        
        product = {
            'name': request.form.get('name'),
            'price': float(request.form.get('price')),
            'discount_price': float(request.form.get('discount_price', 0)),
            'stock': int(request.form.get('stock')),
            'category': request.form.get('category'),
            'description': request.form.get('description'),
            'image': request.form.get('image'),
            'created_at': datetime.utcnow()
        }
        
        products_col.insert_one(product)
        flash('Product added successfully', 'success')
        return redirect(url_for('admin.products'))
    
    return render_template('admin/add_product.html')

@admin_bp.route('/products/<product_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_product(product_id):
    """Edit product"""
    from app import products_col
    
    if request.method == 'POST':
        update_data = {
            'name': request.form.get('name'),
            'price': float(request.form.get('price')),
            'discount_price': float(request.form.get('discount_price', 0)),
            'stock': int(request.form.get('stock')),
            'category': request.form.get('category'),
            'description': request.form.get('description'),
            'image': request.form.get('image')
        }
        
        products_col.update_one(
            {'_id': ObjectId(product_id)},
            {'$set': update_data}
        )
        
        flash('Product updated successfully', 'success')
        return redirect(url_for('admin.products'))
    
    product = products_col.find_one({'_id': ObjectId(product_id)})
    
    if not product:
        flash('Product not found', 'error')
        return redirect(url_for('admin.products'))
    
    return render_template('admin/edit_product.html', product=product)

@admin_bp.route('/products/<product_id>/delete', methods=['POST'])
@admin_required
def delete_product(product_id):
    """Delete product"""
    from app import products_col
    
    result = products_col.delete_one({'_id': ObjectId(product_id)})
    
    if result.deleted_count > 0:
        flash('Product deleted successfully', 'success')
    else:
        flash('Product not found', 'error')
    
    return redirect(url_for('admin.products'))

@admin_bp.route('/orders')
@admin_required
def orders():
    """Order management"""
    from app import orders_col, users_col
    
    all_orders = list(orders_col.find().sort('created_at', -1))
    
    # Enrich with user data
    for order in all_orders:
        user = users_col.find_one({'_id': order['user_id']})
        order['user'] = user
    
    return render_template('admin/orders.html', orders=all_orders)

@admin_bp.route('/orders/<order_id>/assign', methods=['POST'])
@admin_required
def assign_order(order_id):
    """Assign order to delivery agent"""
    from app import orders_col, agents_col, users_col, send_order_notification
    
    agent_id = request.form.get('agent_id')
    
    if not agent_id:
        flash('Please select an agent', 'error')
        return redirect(url_for('admin.orders'))
    
    orders_col.update_one(
        {'_id': ObjectId(order_id)},
        {'$set': {
            'agent_id': ObjectId(agent_id),
            'status': 'assigned_to_agent'
        }}
    )
    
    # Send notification
    order = orders_col.find_one({'_id': ObjectId(order_id)})
    user = users_col.find_one({'_id': order['user_id']})
    send_order_notification(user['email'], order_id, 'assigned_to_agent')
    
    flash('Order assigned successfully', 'success')
    return redirect(url_for('admin.orders'))

@admin_bp.route('/agents')
@admin_required
def agents():
    """Agent management"""
    from app import agents_col
    
    all_agents = list(agents_col.find().sort('created_at', -1))
    
    return render_template('admin/agents.html', agents=all_agents)

@admin_bp.route('/agents/<agent_id>/approve', methods=['POST'])
@admin_required
def approve_agent(agent_id):
    """Approve delivery agent"""
    from app import agents_col, send_agent_approval_email
    
    agent = agents_col.find_one({'_id': ObjectId(agent_id)})
    
    if not agent:
        flash('Agent not found', 'error')
        return redirect(url_for('admin.agents'))
    
    if not agent.get('verified'):
        flash('Agent email must be verified first', 'error')
        return redirect(url_for('admin.agents'))
    
    agents_col.update_one(
        {'_id': ObjectId(agent_id)},
        {'$set': {'approved': True}}
    )
    
    # Send approval email
    send_agent_approval_email(agent['email'], agent['name'])
    
    flash('Agent approved successfully', 'success')
    return redirect(url_for('admin.agents'))

@admin_bp.route('/agents/<agent_id>/remove', methods=['POST'])
@admin_required
def remove_agent(agent_id):
    """Remove delivery agent"""
    from app import agents_col
    
    result = agents_col.delete_one({'_id': ObjectId(agent_id)})
    
    if result.deleted_count > 0:
        flash('Agent removed successfully', 'success')
    else:
        flash('Agent not found', 'error')
    
    return redirect(url_for('admin.agents'))
