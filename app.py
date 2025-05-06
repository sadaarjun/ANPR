import os
import logging
import tempfile
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import threading

# Initialize SQLAlchemy without app
db = SQLAlchemy()

# Global variables for ANPR system components
camera_manager = None
anpr_processor = None

# Create Flask application factory
def create_app():
    # Set up the Flask application
    app = Flask(__name__)
    app.secret_key = os.environ.get("SESSION_SECRET", "anpr_secret_key")
    # Configure session
    from datetime import timedelta
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # 7 days
    app.config['SESSION_COOKIE_SECURE'] = False  # Don't require HTTPS
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Allow redirects with cookies
    app.config['SESSION_COOKIE_PATH'] = '/'  # Allow cookies for all paths
    app.config['SESSION_COOKIE_NAME'] = 'anpr_session'  # Custom session cookie name
    
    # Add a special key for direct authentication cookie
    app.config['AUTH_COOKIE_NAME'] = 'anpr_auth'  # Auth token cookie name
    app.config['AUTH_COOKIE_DURATION'] = 60 * 60 * 24 * 7  # 7 days in seconds
    
    # Increase logging level for debugging
    app.logger.setLevel(logging.DEBUG)
    
    # Set session key prefix
    app.config['SESSION_KEY_PREFIX'] = 'anpr_sess:'
    
    # Configure the database - use PostgreSQL in production, SQLite for development
    database_url = os.environ.get("DATABASE_URL", "sqlite:///anpr.db")
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize SQLAlchemy with the app
    db.init_app(app)

    # Try to import Flask-Login - if it's not available, we'll handle it gracefully
    try:
        from flask_login import LoginManager
        # Initialize Flask-Login
        login_manager = LoginManager()
        login_manager.init_app(app)
        login_manager.login_view = 'auth.login'
        
        # Set up Flask-Login user loader
        from models import User, Vehicle, Log
        
        @login_manager.user_loader
        def load_user(user_id):
            return User.query.get(int(user_id))
        
        # Flag to track if login is available
        app.config['LOGIN_AVAILABLE'] = True
        
    except ImportError:
        logging.warning("Flask-Login not available. Running in limited mode.")
        # Import models without Flask-Login functionality
        from models import Vehicle, Log
        # Flag to track if login is not available
        app.config['LOGIN_AVAILABLE'] = False
    
    with app.app_context():
        # Create database tables
        db.create_all()
    
    # Import and register blueprints
    from routes.auth import auth_bp
    from routes.api import api_bp
    from routes.dashboard import dashboard_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(dashboard_bp)
    
    # Import mock camera and ANPR modules for development
    class MockCameraManager:
        def __init__(self, config=None):
            self.initialized = True
            logging.info("Initialized mock camera manager")
        
        def capture_image(self):
            logging.info("Mock camera: Capturing image")
            return None
    
    class MockANPRProcessor:
        def __init__(self, config=None, camera_manager=None):
            self.processing = False
            logging.info("Initialized mock ANPR processor")
        
        def start_processing(self):
            self.processing = True
            logging.info("Mock ANPR: Started processing")
        
        def stop_processing(self):
            self.processing = False
            logging.info("Mock ANPR: Stopped processing")
    
    # Try to import the real modules - if they're not available, use the mocks
    try:
        from camera_manager import CameraManager
        from anpr_processor import ANPRProcessor
        from config import Config
        
        # Real modules imported successfully
        app.config['USING_MOCKS'] = False
    except ImportError:
        logging.warning("Camera or ANPR modules not available. Using mock classes.")
        CameraManager = MockCameraManager
        ANPRProcessor = MockANPRProcessor
        from config import Config
        
        # Flag to indicate we're using mocks
        app.config['USING_MOCKS'] = True
    
    # Initialize the configuration
    # We'll initialize the config after we have an application context
    app.config['SYSTEM_CONFIG'] = None
    
    # Make current_user available to templates
    @app.context_processor
    def inject_user():
        from routes.auth import current_user
        return {'current_user': current_user}
        
    # Add a before_request handler to initialize the session
    @app.before_request
    def before_request():
        from flask import session, request
        import logging
        # Log the session for debugging
        if request.endpoint != 'static':
            logging.debug(f"Session before request to {request.path}: {session}")
            
        # Make sure session is configured properly
        if 'user_id' in session:
            # Make the session permanent during each request
            session.permanent = True
            session.modified = True
    
    # Create an admin user if none exists
    def create_admin_user(app):
        from werkzeug.security import generate_password_hash
        try:
            with app.app_context():
                from models import User
                if User.query.filter_by(username='admin').first() is None:
                    admin = User(
                        username='admin',
                        email='admin@anpr.local',
                        password_hash=generate_password_hash('admin'),
                        is_admin=True
                    )
                    db.session.add(admin)
                    db.session.commit()
                    logging.info("Admin user created")
        except Exception as e:
            logging.error(f"Error creating admin user: {str(e)}")
    
    # Initialize the camera manager and ANPR processor
    def initialize_system(app):
        global camera_manager, anpr_processor
        try:
            # Initialize the configuration
            from config import Config
            config = Config()
            app.config['SYSTEM_CONFIG'] = config

            # Initialize the camera manager
            camera_manager = CameraManager(config)
            
            # Initialize the ANPR processor
            anpr_processor = ANPRProcessor(config, camera_manager)
            
            # Start the ANPR processing in a separate thread
            anpr_thread = threading.Thread(target=anpr_processor.start_processing)
            anpr_thread.daemon = True
            anpr_thread.start()
            
            logging.info("ANPR system initialized successfully")
            
            # Store in app context for access in routes
            app.config['camera_manager'] = camera_manager
            app.config['anpr_processor'] = anpr_processor
            
        except Exception as e:
            logging.error(f"Failed to initialize ANPR system: {str(e)}")
    
    # Create admin user and initialize system
    with app.app_context():
        create_admin_user(app)
        # Initialize system components
        initialize_system(app)
    
    return app
