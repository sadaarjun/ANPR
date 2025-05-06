from flask import Blueprint, jsonify, request, render_template, current_app, session

# Try to import flask_login, use session-based auth as fallback
try:
    from flask_login import login_required, current_user
except ImportError:
    # Import our custom login_required and current_user from auth.py if flask_login is not available
    from routes.auth import login_required, current_user
from datetime import datetime, timedelta
from models import Vehicle, Log
from app import db
# Note: We access camera_manager and anpr_processor from current_app.config
import logging
import json
import threading
import utils

# Create a blueprint for API routes
api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/anpr/start', methods=['POST'])
@login_required
def start_anpr():
    """Start ANPR processing"""
    if not current_user.is_admin:
        return jsonify({"success": False, "message": "Admin privileges required"}), 403
    
    try:
        anpr_processor = current_app.config.get('anpr_processor')
        if not anpr_processor:
            return jsonify({"success": False, "message": "ANPR processor not initialized"}), 500
        
        # Check if already running
        if anpr_processor.processing:
            return jsonify({"success": True, "message": "ANPR processing already running"})
        
        # Start in a new thread
        anpr_thread = threading.Thread(target=anpr_processor.start_processing)
        anpr_thread.daemon = True
        anpr_thread.start()
        
        logging.info(f"ANPR processing started by user {current_user.username}")
        return jsonify({"success": True, "message": "ANPR processing started"})
        
    except Exception as e:
        logging.error(f"Error starting ANPR processing: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@api_bp.route('/anpr/stop', methods=['POST'])
@login_required
def stop_anpr():
    """Stop ANPR processing"""
    if not current_user.is_admin:
        return jsonify({"success": False, "message": "Admin privileges required"}), 403
    
    try:
        anpr_processor = current_app.config.get('anpr_processor')
        if not anpr_processor:
            return jsonify({"success": False, "message": "ANPR processor not initialized"}), 500
        
        # Check if already stopped
        if not anpr_processor.processing:
            return jsonify({"success": True, "message": "ANPR processing already stopped"})
        
        # Stop processing
        anpr_processor.stop_processing()
        
        logging.info(f"ANPR processing stopped by user {current_user.username}")
        return jsonify({"success": True, "message": "ANPR processing stopped"})
        
    except Exception as e:
        logging.error(f"Error stopping ANPR processing: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@api_bp.route('/camera/capture', methods=['GET'])
@login_required
def capture_image():
    """Capture a single image from the camera"""
    try:
        camera_manager = current_app.config.get('camera_manager')
        if not camera_manager or not hasattr(camera_manager, 'initialized') or not camera_manager.initialized:
            return jsonify({"success": False, "message": "Camera not initialized"}), 500
        
        # Capture image
        image = camera_manager.capture_image()
        if image is None:
            return jsonify({"success": False, "message": "Failed to capture image"}), 500
        
        # Save image to a temp file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_path = f"static/images/captures/temp_{timestamp}.jpg"
        import cv2
        cv2.imwrite(image_path, image)
        
        return jsonify({
            "success": True, 
            "image_url": image_path,
            "timestamp": timestamp
        })
        
    except Exception as e:
        logging.error(f"Error capturing image: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@api_bp.route('/logs/recent', methods=['GET'])
@login_required
def get_recent_logs():
    """Get recent log entries and return as HTML for AJAX updates"""
    try:
        limit = request.args.get('limit', default=10, type=int)
        recent_logs = utils.get_recent_logs(limit)
        
        # Render the logs as HTML
        html = render_template('partials/recent_logs.html', recent_logs=recent_logs)
        
        return jsonify({"success": True, "html": html})
        
    except Exception as e:
        logging.error(f"Error getting recent logs: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@api_bp.route('/logs/today', methods=['GET'])
@login_required
def get_today_logs():
    """Get today's logs, optionally filtered by event type"""
    try:
        event_type = request.args.get('event_type', default=None)
        
        if event_type == 'entry':
            logs = utils.get_today_entries()
        elif event_type == 'exit':
            logs = utils.get_today_exits()
        else:
            today = datetime.now().date()
            today_start = datetime.combine(today, datetime.min.time())
            today_end = datetime.combine(today, datetime.max.time())
            logs = Log.query.filter(Log.timestamp.between(today_start, today_end)).order_by(Log.timestamp.desc()).all()
        
        result = []
        for log in logs:
            result.append({
                "id": log.id,
                "license_plate": log.license_plate,
                "timestamp": log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "event_type": log.event_type,
                "status": log.status,
                "confidence": log.confidence,
                "has_image": log.image_path is not None
            })
        
        return jsonify({"success": True, "logs": result})
        
    except Exception as e:
        logging.error(f"Error getting today's logs: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@api_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Get system statistics"""
    try:
        stats = utils.generate_system_stats()
        return jsonify({"success": True, "stats": stats})
        
    except Exception as e:
        logging.error(f"Error getting system stats: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@api_bp.route('/stats/daily_traffic', methods=['GET'])
@login_required
def get_daily_traffic():
    """Get daily traffic data for charts"""
    try:
        # Get data for the last 7 days
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=6)
        
        dates = []
        entries = []
        exits = []
        
        current_date = start_date
        while current_date <= end_date:
            date_str = current_date.strftime('%Y-%m-%d')
            dates.append(current_date.strftime('%m-%d'))
            
            # Get entries for this date
            day_start = datetime.combine(current_date, datetime.min.time())
            day_end = datetime.combine(current_date, datetime.max.time())
            
            entry_count = Log.query.filter(
                Log.timestamp.between(day_start, day_end),
                Log.event_type == 'entry'
            ).count()
            
            exit_count = Log.query.filter(
                Log.timestamp.between(day_start, day_end),
                Log.event_type == 'exit'
            ).count()
            
            entries.append(entry_count)
            exits.append(exit_count)
            
            current_date += timedelta(days=1)
        
        return jsonify({
            "success": True,
            "labels": dates,
            "entries": entries,
            "exits": exits
        })
        
    except Exception as e:
        logging.error(f"Error getting daily traffic data: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@api_bp.route('/stats/recognition_accuracy', methods=['GET'])
@login_required
def get_recognition_accuracy():
    """Get recognition accuracy data for charts"""
    try:
        # Get counts for different confidence levels
        high_confidence = Log.query.filter(Log.confidence >= 0.9).count()
        medium_confidence = Log.query.filter(Log.confidence.between(0.7, 0.9)).count()
        low_confidence = Log.query.filter(Log.confidence < 0.7).count()
        
        return jsonify({
            "success": True,
            "high": high_confidence,
            "medium": medium_confidence,
            "low": low_confidence
        })
        
    except Exception as e:
        logging.error(f"Error getting recognition accuracy data: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@api_bp.route('/vehicles/search', methods=['GET'])
@login_required
def search_vehicles_api():
    """Search vehicles API endpoint"""
    try:
        query = request.args.get('query', default='', type=str)
        vehicles = utils.search_vehicles(query)
        
        result = []
        for vehicle in vehicles:
            result.append({
                "id": vehicle.id,
                "license_plate": vehicle.license_plate,
                "owner_name": vehicle.owner_name,
                "is_resident": vehicle.is_resident,
                "status": vehicle.status
            })
        
        return jsonify({"success": True, "vehicles": result})
        
    except Exception as e:
        logging.error(f"Error searching vehicles: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@api_bp.route('/settings/update', methods=['POST'])
@login_required
def update_settings():
    """Update system settings"""
    if not current_user.is_admin:
        return jsonify({"success": False, "message": "Admin privileges required"}), 403
    
    try:
        # Get settings data from request
        settings_data = request.json
        
        if not settings_data:
            return jsonify({"success": False, "message": "No settings data provided"}), 400
        
        # Get config instance
        config = current_app.config.get('SYSTEM_CONFIG')
        if not config:
            return jsonify({"success": False, "message": "System configuration not found"}), 500
        
        # Update each setting
        for key, value in settings_data.items():
            success = config.update_setting(key, value)
            if not success:
                return jsonify({"success": False, "message": f"Failed to update setting: {key}"}), 500
        
        return jsonify({
            "success": True,
            "message": "Settings updated successfully"
        })
        
    except Exception as e:
        logging.error(f"Error updating settings: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500
