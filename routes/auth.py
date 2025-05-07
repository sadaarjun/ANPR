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
        
        # Also store a cookie for auth verification
        import json
        import base64
        # Create a token with user ID, username, is_admin, and timestamp
        token_data = {
            'id': user.id,
            'username': user.username,
            'is_admin': user.is_admin,
            'timestamp': datetime.utcnow().timestamp()
        }
        # Convert to JSON and encode as base64
        token_json = json.dumps(token_data)
        token = base64.b64encode(token_json.encode()).decode()
        # Set the auth_token value in the session
        session['auth_token'] = token
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
            # Try to validate using the session first
            logging.debug(f"Session content during auth check: {session}")
            
            # First check if we have a valid session
            if 'user_id' in session:
                logging.debug(f"Authentication successful for user_id={session['user_id']} via session")
                return f(*args, **kwargs)
            
            # If not, check for our auth cookie or token in URL
            import json
            import base64
            try:
                # Get auth token from cookie or URL parameter
                auth_cookie_name = current_app.config.get('AUTH_COOKIE_NAME', 'anpr_auth')
                
                # Debug all cookies and query parameters
                logging.debug(f"All cookies: {request.cookies}")
                logging.debug(f"URL parameters: {request.args}")
                
                # Try to get token from cookie or URL parameter
                auth_token = request.cookies.get(auth_cookie_name) or request.args.get('token')
                
                if auth_token:
                    # We have an auth token, try to decode it
                    logging.debug(f"Found auth token: {auth_token[:20]}...")
                    try:
                        # Debug each step of the decode process
                        decoded_bytes = base64.b64decode(auth_token)
                        logging.debug(f"Base64 decoded: {decoded_bytes[:50]}")
                        
                        decoded_str = decoded_bytes.decode()
                        logging.debug(f"String decoded: {decoded_str[:50]}")
                        
                        token_data = json.loads(decoded_str)
                        logging.debug(f"JSON parsed: {token_data}")
                        
                        # Check if token is not expired (7 days)
                        import time
                        now = time.time()
                        if now - token_data.get('timestamp', 0) <= 60*60*24*7:  # 7 days in seconds
                            # Token is valid, reconstruct the session
                            session['user_id'] = token_data.get('id')
                            session['username'] = token_data.get('username')
                            session['is_admin'] = token_data.get('is_admin')
                            session['authenticated'] = True
                            session['login_timestamp'] = token_data.get('timestamp')
                            
                            # Make sure the session is saved
                            session.modified = True
                            
                            logging.debug(f"Authentication successful for user_id={session['user_id']} via auth token")
                            
                            # Recreate current_user object for this request
                            current_app.config['CURRENT_USER_ID'] = session['user_id']
                            current_app.config['CURRENT_USER_USERNAME'] = session['username']
                            current_app.config['CURRENT_USER_IS_ADMIN'] = session['is_admin']
                            
                            # Return the decorated function
                            return f(*args, **kwargs)
                        else:
                            logging.warning(f"Auth token expired at {request.path}")
                    except Exception as inner_e:
                        logging.error(f"Error decoding token parts: {str(inner_e)}")
            except Exception as e:
                logging.error(f"Error processing auth token: {str(e)}", exc_info=True)
            
            # If we get here, authentication failed
            logging.warning(f"Authentication failed at {request.path} - No valid auth method found")
            return redirect(url_for('auth.login', next=request.url))
        
        decorated_function.__name__ = f.__name__
        decorated_function.__module__ = f.__module__
        return decorated_function
    
    # Create a placeholder current_user object
    class CurrentUser:
        @property
        def is_authenticated(self):
            if 'user_id' in session:
                return True
            # Try to get from app config if set during token auth
            try:
                return current_app.config.get('CURRENT_USER_ID') is not None
            except RuntimeError:
                # If called outside app context
                return False
        
        @property
        def is_admin(self):
            if 'is_admin' in session:
                return session.get('is_admin', False)
            # Try to get from app config if set during token auth
            try:
                return current_app.config.get('CURRENT_USER_IS_ADMIN', False)
            except RuntimeError:
                # If called outside app context
                return False
        
        @property
        def username(self):
            if 'username' in session:
                return session.get('username', '')
            # Try to get from app config if set during token auth
            try:
                return current_app.config.get('CURRENT_USER_USERNAME', '')
            except RuntimeError:
                # If called outside app context
                return ''
        
        @property
        def id(self):
            if 'user_id' in session:
                return session.get('user_id', None)
            # Try to get from app config if set during token auth
            try:
                return current_app.config.get('CURRENT_USER_ID')
            except RuntimeError:
                # If called outside app context
                return None
                
        @property
        def created_at(self):
            # Get the user from the database to access the created_at field
            if self.id:
                user = User.query.get(self.id)
                if user:
                    return user.created_at
            return datetime.utcnow()  # Fallback
            
        @property
        def last_login(self):
            # Get the user from the database to access the last_login field
            if self.id:
                user = User.query.get(self.id)
                if user:
                    return user.last_login
            return None
            
        @property
        def email(self):
            # Get the user from the database to access the email field
            if self.id:
                user = User.query.get(self.id)
                if user:
                    return user.email
            return ''
    
    current_user = CurrentUser()
    
    # Function to generate URLs with the auth token appended
    def url_with_token(endpoint, **values):
        """Generate a URL with the auth token appended if available"""
        url = url_for(endpoint, **values)
        
        # Make sure we have a request context
        from flask import has_request_context
        
        # First check if we have an auth token in the URL parameters
        if has_request_context() and request.args.get('token'):
            token = request.args.get('token')
            url += ('&' if '?' in url else '?') + 'token=' + token
        # Otherwise check if we have an auth token in the session
        elif session and 'auth_token' in session and session['auth_token'] is not None:
            url += ('&' if '?' in url else '?') + 'token=' + session['auth_token']
        
        return url

from werkzeug.security import check_password_hash, generate_password_hash

# Create a blueprint for authentication routes
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    # If user is already authenticated, redirect to dashboard
    # Skip this check when there's no token in the URL - this prevents redirect loops
    if current_user.is_authenticated and request.args.get('token'):
        logging.debug("User already authenticated, redirecting to dashboard")
        return redirect(url_with_token('dashboard.index'))
    elif current_user.is_authenticated and 'auth_token' in session and session['auth_token']:
        logging.debug("User already authenticated via session, redirecting to dashboard")
        return redirect(url_with_token('dashboard.index'))
    
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
        
        # Add auth token to session and use URL parameters as a fallback
        from datetime import timedelta
        logging.debug(f"Session cookie before setting: {session.get('user_id')}")
        logging.debug(f"Auth token value: {session.get('auth_token')[:20]}...")
        
        # Get the auth cookie name from config
        auth_cookie_name = current_app.config.get('AUTH_COOKIE_NAME', 'anpr_auth')
        auth_cookie_duration = current_app.config.get('AUTH_COOKIE_DURATION', 60*60*24*7)  # 7 days
        
        # Set the auth token as a direct cookie
        max_age = auth_cookie_duration
        expires = datetime.utcnow() + timedelta(seconds=auth_cookie_duration)
        resp.set_cookie(
            auth_cookie_name,          # Use the auth cookie name
            session['auth_token'],      # Use the auth token from the session
            max_age=max_age,           # Cookie duration
            expires=expires,           # Also set expires
            path='/',                  # Allow all paths
            httponly=True,             # Prevent JavaScript access
            samesite='Lax',            # Allow redirects
            secure=False               # Don't require HTTPS
        )
        
        logging.debug(f"Set auth cookie '{auth_cookie_name}' with token value {session['auth_token'][:20]}...")
        
        # Also set the standard session cookie
        cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'session')
        std_cookie = request.cookies.get('session', '')
        if std_cookie:
            logging.debug(f"Setting session cookie '{cookie_name}' as a backup")
            resp.set_cookie(
                cookie_name,
                std_cookie,
                max_age=max_age,
                expires=expires,
                path='/',
                httponly=True,
                samesite='Lax',
                secure=False
            )
            
        # Add an auth token as URL parameter as a fallback
        # Redirect to dashboard with token parameter
        next_page = request.args.get('next')
        
        # Create a URL with a token parameter
        url = url_for('dashboard.index', token=session['auth_token'])
        if next_page:
            url = next_page + ('&' if '?' in next_page else '?') + 'token=' + session['auth_token']
        
        logging.debug(f"Redirecting to URL with token: {url[:50]}...")
        resp = redirect(url)
        
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
    
    # Clear all cookies
    cookie_name = current_app.config.get('SESSION_COOKIE_NAME', 'session')
    auth_cookie_name = current_app.config.get('AUTH_COOKIE_NAME', 'anpr_auth')
    logging.debug(f"Deleting cookies: 'session', '{cookie_name}' and '{auth_cookie_name}'")
    resp.delete_cookie('session')
    resp.delete_cookie(cookie_name)
    resp.delete_cookie(auth_cookie_name)
    
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
