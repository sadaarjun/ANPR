from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app, session
from datetime import datetime, timedelta
import logging
from models import User
from app import db

# Try to import flask_login functions, create placeholders if not available
try:
    from flask_login import login_user, logout_user, login_required, current_user
    login_available = True
except ImportError:
    login_available = False
    
    # Create placeholder functions
    def login_user(user, remember=False):
        # Store user information in session
        session.clear()  # Clear any existing session data
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = user.is_admin
        session['authenticated'] = True
        session['login_timestamp'] = datetime.utcnow().timestamp()
        # Make sure the session is saved properly
        session.modified = True
        # Force set session permanency based on remember flag
        session.permanent = True
        logging.debug(f"Created session with user_id={user.id}, username={user.username}")
        return True
    
    def logout_user():
        # Clear all session data
        session.clear()
        session.modified = True
        logging.debug("Session cleared during logout")
        return True
    
    # Create a placeholder decorator
    def login_required(f):
        def decorated_function(*args, **kwargs):
            logging.debug(f"Session content during auth check: {session}")
            if 'user_id' not in session:
                logging.warning(f"Authentication failed at {request.path} - No user_id in session")
                return redirect(url_for('auth.login', next=request.url))
            logging.debug(f"Authentication successful for user_id={session['user_id']}")
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        decorated_function.__module__ = f.__module__
        return decorated_function
    
    # Create a placeholder current_user object
    class CurrentUser:
        @property
        def is_authenticated(self):
            return 'user_id' in session
        
        @property
        def is_admin(self):
            return session.get('is_admin', False)
        
        @property
        def username(self):
            return session.get('username', '')
        
        @property
        def id(self):
            return session.get('user_id', None)
    
    current_user = CurrentUser()

from werkzeug.security import check_password_hash, generate_password_hash

# Create a blueprint for authentication routes
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    # If user is already authenticated, redirect to dashboard
    if current_user.is_authenticated:
        logging.debug("User already authenticated, redirecting to dashboard")
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        # Validate input
        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return render_template('login.html', current_year=datetime.now().year)
        
        # Check if user exists
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password. Please try again.', 'danger')
            return render_template('login.html', current_year=datetime.now().year)
        
        # Log in the user
        login_user(user, remember=remember)
        
        # Update last login timestamp
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Debug information for session
        logging.debug(f"Session after login: {session}")
        logging.debug(f"Is authenticated: {current_user.is_authenticated}")
        
        # Force save session
        session.modified = True
        
        # Log successful login
        logging.info(f"User {username} logged in successfully")
        
        # Debug the headers and cookies
        logging.debug(f"Request cookies at login time: {request.cookies}")
        
        # Create response with redirect
        resp = redirect(url_for('dashboard.index'))
        
        # Set session cookie explicitly with secure settings
        from datetime import timedelta
        logging.debug(f"Session cookie before setting: {session.get('user_id')}")
        cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'session')
        logging.debug(f"Using configured cookie name: {cookie_name}")
        
        # Get both the standard and custom cookie values
        std_cookie = request.cookies.get('session', '')
        custom_cookie = request.cookies.get(cookie_name, '')
        logging.debug(f"Standard cookie value: {std_cookie[:5]}..., Custom cookie value: {custom_cookie[:5]}...")
        
        # Use the cookie value that's present, prefer the custom one
        cookie_val = custom_cookie if custom_cookie else std_cookie
        
        if not login_available or True:  # Always set the cookie for now for debugging
            logging.debug(f"Setting session cookie on response: {cookie_val[:10] if cookie_val else 'empty'}")
            # Set the cookie with more explicit parameters
            max_age = 86400 * 7  # 7 days in seconds
            expires = datetime.utcnow() + timedelta(days=7)
            resp.set_cookie(
                cookie_name,              # Use the configured cookie name
                cookie_val,               # Use the value from the request
                max_age=max_age,          # 7 days in seconds
                expires=expires,          # Also set expires
                path='/',                 # Allow all paths
                httponly=True,            # No JavaScript access
                samesite='Lax',           # Allow redirects
                secure=False              # Don't require HTTPS
            )
        
        # Redirect to the requested page or dashboard
        next_page = request.args.get('next')
        if next_page:
            resp = redirect(next_page)
        logging.debug(f"Final response to be returned: {resp}")
        return resp
    
    # GET request - render login form
    return render_template('login.html', current_year=datetime.now().year)

@auth_bp.route('/logout')
@login_required
def logout():
    """User logout route"""
    username = current_user.username
    logout_user()
    flash('You have been logged out successfully', 'success')
    logging.info(f"User {username} logged out")
    
    # Create response with redirect
    resp = redirect(url_for('auth.login'))
    
    # Clear both session cookie and custom cookie
    cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'session')
    logging.debug(f"Deleting cookies: 'session' and '{cookie_name}'")
    resp.delete_cookie('session')
    resp.delete_cookie(cookie_name)
    
    return resp

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile route"""
    if request.method == 'POST':
        # Get form data
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        user = User.query.get(current_user.id)
        
        # Update email if provided
        if email and email != user.email:
            # Check if email is already in use
            if User.query.filter_by(email=email).first() and User.query.filter_by(email=email).first().id != user.id:
                flash('Email is already in use', 'danger')
                return redirect(url_for('auth.profile'))
            
            user.email = email
            flash('Email updated successfully', 'success')
        
        # Update password if provided
        if current_password and new_password and confirm_password:
            # Verify current password
            if not check_password_hash(user.password_hash, current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('auth.profile'))
            
            # Verify new password and confirmation match
            if new_password != confirm_password:
                flash('New passwords do not match', 'danger')
                return redirect(url_for('auth.profile'))
            
            # Update password
            user.password_hash = generate_password_hash(new_password)
            flash('Password updated successfully', 'success')
        
        # Commit changes to database
        db.session.commit()
        return redirect(url_for('auth.profile'))
    
    return render_template('profile.html', current_year=datetime.now().year)

@auth_bp.route('/users', methods=['GET'])
@login_required
def users():
    """List all users (admin only)"""
    if not current_user.is_admin:
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('dashboard.index'))
    
    users = User.query.all()
    return render_template('users.html', users=users, current_year=datetime.now().year)

@auth_bp.route('/add_user', methods=['POST'])
@login_required
def add_user():
    """Add a new user (admin only)"""
    if not current_user.is_admin:
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('dashboard.index'))
    
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    is_admin = True if request.form.get('is_admin') else False
    
    # Validate input
    if not username or not email or not password:
        flash('Please fill all required fields', 'danger')
        return redirect(url_for('auth.users'))
    
    # Check if username is already taken
    if User.query.filter_by(username=username).first():
        flash('Username is already taken', 'danger')
        return redirect(url_for('auth.users'))
    
    # Check if email is already taken
    if User.query.filter_by(email=email).first():
        flash('Email is already in use', 'danger')
        return redirect(url_for('auth.users'))
    
    # Create new user
    new_user = User(
        username=username,
        email=email,
        password_hash=generate_password_hash(password),
        is_admin=is_admin,
        created_at=datetime.utcnow()
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    flash(f'User {username} created successfully', 'success')
    logging.info(f"Admin {current_user.username} created new user: {username}")
    
    return redirect(url_for('auth.users'))

@auth_bp.route('/edit_user', methods=['POST'])
@login_required
def edit_user():
    """Edit an existing user (admin only)"""
    if not current_user.is_admin:
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('dashboard.index'))
    
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')
    new_password = request.form.get('new_password')
    is_admin = True if request.form.get('is_admin') else False
    
    # Get user by ID
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('auth.users'))
    
    # Cannot edit own admin status
    if user.id == current_user.id and not is_admin:
        flash('You cannot remove your own admin status', 'danger')
        return redirect(url_for('auth.users'))
    
    # Update username if changed
    if username and username != user.username:
        # Check if username is already taken
        if User.query.filter_by(username=username).first() and User.query.filter_by(username=username).first().id != user.id:
            flash('Username is already taken', 'danger')
            return redirect(url_for('auth.users'))
        
        user.username = username
    
    # Update email if changed
    if email and email != user.email:
        # Check if email is already taken
        if User.query.filter_by(email=email).first() and User.query.filter_by(email=email).first().id != user.id:
            flash('Email is already in use', 'danger')
            return redirect(url_for('auth.users'))
        
        user.email = email
    
    # Update password if provided
    if new_password:
        user.password_hash = generate_password_hash(new_password)
    
    # Update admin status
    user.is_admin = is_admin
    
    db.session.commit()
    
    flash(f'User {user.username} updated successfully', 'success')
    logging.info(f"Admin {current_user.username} updated user: {user.username}")
    
    return redirect(url_for('auth.users'))

@auth_bp.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    """Delete a user (admin only)"""
    if not current_user.is_admin:
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('dashboard.index'))
    
    user_id = request.form.get('user_id')
    
    # Get user by ID
    user = User.query.get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('auth.users'))
    
    # Cannot delete own account
    if user.id == current_user.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('auth.users'))
    
    # Get username for logging before deletion
    username = user.username
    
    # Delete user
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} deleted successfully', 'success')
    logging.info(f"Admin {current_user.username} deleted user: {username}")
    
    return redirect(url_for('auth.users'))
