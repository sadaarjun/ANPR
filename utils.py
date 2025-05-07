import os
import logging
import time
import threading
import shutil

# Try to import OpenCV - if it's not available, provide a mock version
try:
    import cv2
    HAS_OPENCV = True
except ImportError:
    logging.warning("OpenCV (cv2) is not available. Image processing functions will be limited.")
    HAS_OPENCV = False
    
    # Define a mock cv2 module with required functions
    class MockCV2:
        @staticmethod
        def imread(path):
            logging.warning(f"Mock cv2.imread called for {path}")
            return None
            
        @staticmethod
        def imwrite(path, img):
            logging.warning(f"Mock cv2.imwrite called for {path}")
            return True
            
    # Create a mock cv2 module
    if not HAS_OPENCV:
        cv2 = MockCV2()
from datetime import datetime, timedelta
from models import Log, Vehicle
from app import db

def cleanup_old_images(config):
    """Clean up old images based on retention period"""
    try:
        retention_days = config.get_image_retention_days()
        if retention_days <= 0:
            return  # No cleanup if retention is set to 0 or negative
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        images_dir = "static/images/captures"
        
        # Get list of image files
        if not os.path.exists(images_dir):
            return
        
        files = os.listdir(images_dir)
        deleted_count = 0
        
        for file in files:
            if file.endswith('.jpg') or file.endswith('.png'):
                file_path = os.path.join(images_dir, file)
                file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                
                if file_mtime < cutoff_date:
                    os.remove(file_path)
                    deleted_count += 1
        
        logging.info(f"Cleaned up {deleted_count} old images")
        
        # Also update the database to mark image paths as deleted
        logs = Log.query.filter(Log.timestamp < cutoff_date, Log.image_path != None).all()
        for log in logs:
            log.image_path = None
        
        db.session.commit()
        
    except Exception as e:
        logging.error(f"Error cleaning up old images: {str(e)}")

def generate_system_stats():
    """Generate system statistics"""
    stats = {}
    
    try:
        # Count total vehicles
        stats['total_vehicles'] = Vehicle.query.count()
        
        # Count resident vehicles
        stats['resident_vehicles'] = Vehicle.query.filter_by(is_resident=True).count()
        
        # Count total logs
        stats['total_logs'] = Log.query.count()
        
        # Count today's logs
        today = datetime.now().date()
        today_start = datetime.combine(today, datetime.min.time())
        today_end = datetime.combine(today, datetime.max.time())
        stats['today_logs'] = Log.query.filter(Log.timestamp.between(today_start, today_end)).count()
        
        # Count today's entries and exits
        stats['today_entries'] = Log.query.filter(
            Log.timestamp.between(today_start, today_end),
            Log.event_type == 'entry'
        ).count()
        
        stats['today_exits'] = Log.query.filter(
            Log.timestamp.between(today_start, today_end),
            Log.event_type == 'exit'
        ).count()
        
        # Get success and error counts
        stats['success_count'] = Log.query.filter_by(status='success').count()
        stats['error_count'] = Log.query.filter_by(status='error').count()
        
        # Get system uptime (just a placeholder, would need proper implementation on RPi)
        stats['uptime'] = "Unknown"  # Would be implemented differently on actual RPi
        
        # Get disk usage
        stats['disk_usage'] = get_disk_usage()
        
    except Exception as e:
        logging.error(f"Error generating system stats: {str(e)}")
    
    return stats

def get_disk_usage():
    """Get disk usage information"""
    try:
        import shutil
        total, used, free = shutil.disk_usage("/")
        total_gb = total / (1024 ** 3)
        used_gb = used / (1024 ** 3)
        free_gb = free / (1024 ** 3)
        percent_used = (used / total) * 100
        
        return {
            'total_gb': round(total_gb, 2),
            'used_gb': round(used_gb, 2),
            'free_gb': round(free_gb, 2),
            'percent_used': round(percent_used, 2)
        }
    except Exception as e:
        logging.error(f"Error getting disk usage: {str(e)}")
        return {
            'total_gb': 0,
            'used_gb': 0,
            'free_gb': 0,
            'percent_used': 0
        }

def get_recent_logs(limit=10):
    """Get recent log entries"""
    try:
        logs = Log.query.order_by(Log.timestamp.desc()).limit(limit).all()
        return logs
    except Exception as e:
        logging.error(f"Error getting recent logs: {str(e)}")
        return []

def get_today_entries():
    """Get today's entries"""
    try:
        today = datetime.now().date()
        today_start = datetime.combine(today, datetime.min.time())
        today_end = datetime.combine(today, datetime.max.time())
        
        entries = Log.query.filter(
            Log.timestamp.between(today_start, today_end),
            Log.event_type == 'entry'
        ).order_by(Log.timestamp.desc()).all()
        
        return entries
    except Exception as e:
        logging.error(f"Error getting today's entries: {str(e)}")
        return []

def get_today_exits():
    """Get today's exits"""
    try:
        today = datetime.now().date()
        today_start = datetime.combine(today, datetime.min.time())
        today_end = datetime.combine(today, datetime.max.time())
        
        exits = Log.query.filter(
            Log.timestamp.between(today_start, today_end),
            Log.event_type == 'exit'
        ).order_by(Log.timestamp.desc()).all()
        
        return exits
    except Exception as e:
        logging.error(f"Error getting today's exits: {str(e)}")
        return []

def search_vehicles(query):
    """Search for vehicles by license plate or owner information"""
    try:
        query = f"%{query}%"
        # Use _license_plate for database column instead of property
        vehicles = Vehicle.query.filter(
            (Vehicle._license_plate.like(query)) | 
            (Vehicle.owner_name.like(query)) | 
            (Vehicle.owner_phone.like(query))
        ).all()
        
        return vehicles
    except Exception as e:
        logging.error(f"Error searching vehicles: {str(e)}")
        return []

def search_logs(query, start_date=None, end_date=None):
    """Search for logs by license plate with optional date range"""
    try:
        # Convert query to uppercase to match license plate format and use like or ilike consistently
        query = f"%{query.upper()}%"
        base_query = Log.query.filter(Log.license_plate.like(query))
        
        if start_date:
            start_datetime = datetime.combine(start_date, datetime.min.time())
            base_query = base_query.filter(Log.timestamp >= start_datetime)
        
        if end_date:
            end_datetime = datetime.combine(end_date, datetime.max.time())
            base_query = base_query.filter(Log.timestamp <= end_datetime)
        
        logs = base_query.order_by(Log.timestamp.desc()).all()
        
        return logs
    except Exception as e:
        logging.error(f"Error searching logs: {str(e)}")
        return []

def format_datetime(dt):
    """Format a datetime object for display"""
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def format_date(dt):
    """Format a datetime object to show only the date"""
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d")

def get_confidence_color(confidence):
    """Get a color class based on confidence level"""
    if confidence is None:
        return "text-secondary"
    elif confidence >= 0.9:
        return "text-success"
    elif confidence >= 0.7:
        return "text-info"
    elif confidence >= 0.5:
        return "text-warning"
    else:
        return "text-danger"
