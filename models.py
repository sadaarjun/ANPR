from datetime import datetime
from app import db

# Try to import UserMixin from flask_login, use a placeholder if not available
try:
    from flask_login import UserMixin
    user_mixin_base = UserMixin
except ImportError:
    # Create a basic placeholder if flask_login is not available
    class UserMixinPlaceholder:
        def get_id(self):
            return str(self.id)
        
        @property
        def is_authenticated(self):
            return True
        
        @property
        def is_active(self):
            return True
            
        @property
        def is_anonymous(self):
            return False
    
    user_mixin_base = UserMixinPlaceholder

# Fix timedelta import
from datetime import timedelta
import secrets

class User(user_mixin_base, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    auth_token = db.Column(db.String(64), unique=True, nullable=True)
    token_expiration = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def generate_auth_token(self):
        """Generate a secure token for user authentication"""
        self.auth_token = secrets.token_hex(32)  # 64 character hex string
        self.token_expiration = datetime.utcnow() + timedelta(days=7)
        return self.auth_token
        
    @classmethod
    def verify_auth_token(cls, token):
        """Verify a token and return the associated user"""
        user = cls.query.filter_by(auth_token=token).first()
        if user and user.token_expiration and user.token_expiration > datetime.utcnow():
            return user
        return None

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_plate = db.Column(db.String(20), unique=True, nullable=False)
    owner_name = db.Column(db.String(100))
    owner_phone = db.Column(db.String(20))
    vehicle_type = db.Column(db.String(50))
    mygate_id = db.Column(db.String(100))
    status = db.Column(db.String(20), default='active')  # active, blacklisted, etc.
    is_resident = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    logs = db.relationship('Log', backref='vehicle', lazy='dynamic')

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'))
    license_plate = db.Column(db.String(20), nullable=False)
    confidence = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    image_path = db.Column(db.String(255))
    event_type = db.Column(db.String(20))  # entry, exit
    processed_by_mygate = db.Column(db.Boolean, default=False)
    mygate_response = db.Column(db.Text)
    status = db.Column(db.String(50))  # success, error, pending
    error_message = db.Column(db.Text)

class Setting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    type = db.Column(db.String(20))  # text, number, boolean
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
