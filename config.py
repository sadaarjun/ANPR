import os
import json
import logging

# We'll import models and db within methods as needed to avoid circular imports
database_available = True

class Config:
    """Configuration manager for the ANPR system"""
    
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.default_config = {
            # Camera settings
            "camera": {
                "resolution": [1920, 1080],
                "framerate": 30,
                "rotation": 0,
                "continuous_capture": True,
                "max_image_width": 1280,
                "enhance_contrast": True
            },
            # ANPR settings
            "anpr": {
                "processing_interval": 2,  # seconds
                "confidence_threshold": 0.7,
                "auto_register_vehicles": True
            },
            # MyGate API settings
            "mygate": {
                "community_id": "",
                "device_id": "",
                "entry_point_name": "Main Gate"
            },
            # System settings
            "system": {
                "debug_mode": True,
                "log_level": "INFO",
                "image_retention_days": 30
            }
        }
        
        # Load configuration from database if available, otherwise from file
        self.load_config()
    
    def load_config(self):
        """Load configuration from database or file"""
        try:
            # Try to load from database first if available
            if database_available:
                try:
                    from flask import current_app
                    # Import within application context
                    with current_app.app_context():
                        from app import db
                        from models import Setting
                        settings = Setting.query.all()
                    if settings:
                        # Configuration exists in database
                        self.config = self.default_config.copy()
                        for setting in settings:
                            self.set_nested_dict_value(self.config, setting.key.split('.'), self.parse_value(setting.value, setting.type))
                        return
                except Exception as db_err:
                    logging.warning(f"Error accessing database settings: {str(db_err)}")
            
            # If database not available or no settings found, try file
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            else:
                # Use default configuration
                self.config = self.default_config.copy()
                # Save to file
                self.save_config_to_file()
            
            # Save to database if available
            if database_available:
                self.save_config_to_db()
        except Exception as e:
            logging.error(f"Error loading configuration: {str(e)}")
            self.config = self.default_config.copy()
    
    def save_config_to_file(self):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving configuration to file: {str(e)}")
    
    def save_config_to_db(self):
        """Save configuration to database"""
        if not database_available:
            logging.warning("Database not available. Skipping save to database.")
            return
        
        try:
            # Import modules within the function to avoid circular imports
            from flask import current_app
            from app import db
            from models import Setting
            
            # Flatten the configuration dictionary
            flat_config = self.flatten_dict(self.config)
            
            # Save each key-value pair to the database
            for key, value in flat_config.items():
                # Determine the value type
                if isinstance(value, bool):
                    value_type = 'boolean'
                    value_str = str(value).lower()
                elif isinstance(value, (int, float)):
                    value_type = 'number'
                    value_str = str(value)
                else:
                    value_type = 'text'
                    value_str = str(value)
                
                # Check if the setting already exists
                setting = Setting.query.filter_by(key=key).first()
                if setting:
                    # Update existing setting
                    setting.value = value_str
                    setting.type = value_type
                else:
                    # Create new setting
                    setting = Setting(key=key, value=value_str, type=value_type)
                    db.session.add(setting)
            
            db.session.commit()
        except Exception as e:
            try:
                db.session.rollback()
            except:
                pass
            logging.error(f"Error saving configuration to database: {str(e)}")
    
    def flatten_dict(self, d, parent_key='', sep='.'):
        """Flatten a nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self.flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    
    def set_nested_dict_value(self, d, keys, value):
        """Set a value in a nested dictionary"""
        if len(keys) == 1:
            d[keys[0]] = value
        else:
            if keys[0] not in d:
                d[keys[0]] = {}
            self.set_nested_dict_value(d[keys[0]], keys[1:], value)
    
    def parse_value(self, value_str, value_type):
        """Parse a string value to its correct type"""
        if value_type == 'boolean':
            return value_str.lower() == 'true'
        elif value_type == 'number':
            try:
                if '.' in value_str:
                    return float(value_str)
                else:
                    return int(value_str)
            except:
                return 0
        else:
            return value_str
    
    def get_camera_resolution(self):
        """Get the camera resolution"""
        return tuple(self.config['camera']['resolution'])
    
    def get_camera_framerate(self):
        """Get the camera framerate"""
        return self.config['camera']['framerate']
    
    def get_camera_rotation(self):
        """Get the camera rotation"""
        return self.config['camera']['rotation']
    
    def get_continuous_capture(self):
        """Get the continuous capture setting"""
        return self.config['camera']['continuous_capture']
    
    def get_max_image_width(self):
        """Get the maximum image width"""
        return self.config['camera']['max_image_width']
    
    def get_enhance_contrast(self):
        """Get the enhance contrast setting"""
        return self.config['camera']['enhance_contrast']
    
    def get_processing_interval(self):
        """Get the ANPR processing interval in seconds"""
        return self.config['anpr']['processing_interval']
    
    def get_confidence_threshold(self):
        """Get the confidence threshold for ANPR"""
        return self.config['anpr']['confidence_threshold']
    
    def get_auto_register_vehicles(self):
        """Get the auto register vehicles setting"""
        return self.config['anpr']['auto_register_vehicles']
    
    def get_community_id(self):
        """Get the MyGate community ID"""
        return self.config['mygate']['community_id']
    
    def get_device_id(self):
        """Get the MyGate device ID"""
        return self.config['mygate']['device_id']
    
    def get_entry_point_name(self):
        """Get the entry point name"""
        return self.config['mygate']['entry_point_name']
    
    def get_debug_mode(self):
        """Get the debug mode setting"""
        return self.config['system']['debug_mode']
    
    def get_log_level(self):
        """Get the log level"""
        return self.config['system']['log_level']
    
    def get_image_retention_days(self):
        """Get the image retention period in days"""
        return self.config['system']['image_retention_days']
    
    def update_setting(self, key, value):
        """Update a setting value"""
        try:
            from app import db
            from models import Setting
            # Update in the database
            setting = Setting.query.filter_by(key=key).first()
            if setting:
                # Determine the value type
                if isinstance(value, bool):
                    value_type = 'boolean'
                    value_str = str(value).lower()
                elif isinstance(value, (int, float)):
                    value_type = 'number'
                    value_str = str(value)
                else:
                    value_type = 'text'
                    value_str = str(value)
                
                setting.value = value_str
                setting.type = value_type
                db.session.commit()
            
            # Update in the config dictionary
            keys = key.split('.')
            self.set_nested_dict_value(self.config, keys, value)
            
            # Save to file
            self.save_config_to_file()
            
            return True
        except Exception as e:
            try:
                db.session.rollback()
            except Exception:
                pass
            logging.error(f"Error updating setting: {str(e)}")
            return False
