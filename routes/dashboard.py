from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app, jsonify, session

# Try to import flask_login, use session-based auth as fallback
try:
    from flask_login import login_required, current_user
except ImportError:
    # Import our custom login_required and current_user from auth.py if flask_login is not available
    from routes.auth import login_required, current_user, url_with_token
from datetime import datetime, timedelta
import base64
import os
import logging
from models import Vehicle, Log, Setting
from app import db
import utils

# Try to import OpenCV - if it's not available, use our mock from utils
try:
    import cv2
    HAS_OPENCV = True
except ImportError:
    logging.warning("OpenCV (cv2) is not available in dashboard routes. Using mock version.")
    from utils import cv2, HAS_OPENCV

# Create a blueprint for dashboard routes
dashboard_bp = Blueprint('dashboard', __name__, url_prefix='')

# Helper function to redirect with token - use this instead of redirect(url_for(...))
def secure_redirect(endpoint, **kwargs):
    """Wrapper for redirect that ensures auth token is included"""
    return redirect(url_with_token(endpoint, **kwargs))

@dashboard_bp.route('/')
@login_required
def index():
    """Dashboard home page"""
    try:
        # Get system stats with proper error handling
        try:
            stats = utils.generate_system_stats()
            if 'disk_usage' not in stats or stats['disk_usage'] is None:
                stats['disk_usage'] = {
                    'total_gb': 0,
                    'used_gb': 0,
                    'free_gb': 0,
                    'percent_used': 0
                }
        except Exception as stats_err:
            logging.error(f"Error generating system stats: {str(stats_err)}")
            stats = {
                'total_vehicles': 0,
                'total_logs': 0,
                'resident_vehicles': 0,
                'visitor_vehicles': 0,
                'today_logs': 0,
                'today_entries': 0,
                'today_exits': 0,
                'success_count': 0,
                'error_count': 0,
                'uptime': 'Unknown',
                'disk_usage': {
                    'total_gb': 0,
                    'used_gb': 0,
                    'free_gb': 0,
                    'percent_used': 0
                }
            }
        
        # Get recent logs
        recent_logs = utils.get_recent_logs(10)
        
        # Check ANPR processor status
        anpr_status = False
        anpr_processor = current_app.config.get('anpr_processor')
        if anpr_processor:
            anpr_status = anpr_processor.processing
        
        # Check camera status
        camera_status = False
        camera_manager = current_app.config.get('camera_manager')
        if camera_manager and hasattr(camera_manager, 'initialized'):
            camera_status = camera_manager.initialized
        
        # Check MyGate API status by seeing if the API key is set
        mygate_api_key = os.environ.get("MYGATE_API_KEY", "")
        mygate_status = mygate_api_key != ""
        
        # Get camera image if available
        camera_image = None
        if camera_status:
            try:
                # Capture image from camera
                image = camera_manager.capture_image()
                if image is not None:
                    # Save temporary image for display
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    temp_path = f"static/images/captures/dashboard_{timestamp}.jpg"
                    cv2.imwrite(temp_path, image)
                    camera_image = '/' + temp_path
            except Exception as e:
                logging.error(f"Error capturing camera image for dashboard: {str(e)}")
        
        # Get configuration values for display
        config = current_app.config.get('SYSTEM_CONFIG')
        community_id = config.get_community_id() if config else ""
        device_id = config.get_device_id() if config else ""
        camera_resolution = f"{config.get_camera_resolution()[0]}x{config.get_camera_resolution()[1]}" if config else "Unknown"
        processing_interval = config.get_processing_interval() if config else 0
        log_retention = config.get_image_retention_days() if config else 30
        
        # Enable auto-refresh for the dashboard
        auto_refresh = True
        refresh_interval = 30  # seconds
        
        return render_template(
            'dashboard.html',
            stats=stats,
            recent_logs=recent_logs,
            anpr_status=anpr_status,
            camera_status=camera_status,
            mygate_status=mygate_status,
            camera_image=camera_image,
            community_id=community_id,
            device_id=device_id,
            camera_resolution=camera_resolution,
            processing_interval=processing_interval,
            log_retention=log_retention,
            auto_refresh=auto_refresh,
            refresh_interval=refresh_interval,
            current_year=datetime.now().year
        )
    except Exception as e:
        logging.error(f"Error rendering dashboard: {str(e)}")
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return render_template('dashboard.html', current_year=datetime.now().year)

@dashboard_bp.route('/vehicles')
@login_required
def vehicles():
    """Vehicles management page"""
    # Get filter parameters
    search = request.args.get('search', '')
    status = request.args.get('status', '')
    type_filter = request.args.get('type', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Build query based on filters
    query = Vehicle.query
    
    if search:
        # Convert to uppercase for license plate matching, use _license_plate column
        query = query.filter(
            (Vehicle._license_plate.ilike(f'%{search.upper()}%')) |
            (Vehicle.owner_name.ilike(f'%{search}%')) |
            (Vehicle.owner_phone.ilike(f'%{search}%'))
        )
    
    if status:
        query = query.filter(Vehicle.status == status)
    
    if type_filter == 'resident':
        query = query.filter(Vehicle.is_resident == True)
    elif type_filter == 'visitor':
        query = query.filter(Vehicle.is_resident == False)
    
    # Order by creation date, newest first
    query = query.order_by(Vehicle.created_at.desc())
    
    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    vehicles = pagination.items
    
    return render_template(
        'vehicles.html',
        vehicles=vehicles,
        pagination=pagination,
        search=search,
        status=status,
        type=type_filter,
        Log=Log,  # Pass the Log model to the template
        current_year=datetime.now().year
    )

@dashboard_bp.route('/add_vehicle', methods=['POST'])
@login_required
def add_vehicle():
    """Add a new vehicle"""
    try:
        # Get form data
        license_plate = request.form.get('license_plate')
        owner_name = request.form.get('owner_name')
        owner_phone = request.form.get('owner_phone')
        flat_unit_number = request.form.get('flat_unit_number')
        vehicle_type = request.form.get('vehicle_type')
        status = request.form.get('status', 'active')
        is_resident = True if request.form.get('is_resident') else False
        notes = request.form.get('notes')
        
        # Validate license plate
        if not license_plate:
            flash('License plate is required', 'danger')
            return secure_redirect('dashboard.vehicles')
        
        # Check if vehicle already exists (case insensitive)
        # Use the _license_plate column which stores uppercase values
        # Convert input to uppercase to match the database storage
        existing_vehicle = Vehicle.query.filter(Vehicle._license_plate == license_plate.upper()).first()
        if existing_vehicle:
            flash(f'Vehicle with license plate {license_plate} already exists', 'danger')
            return secure_redirect('dashboard.vehicles')
        
        # Create new vehicle
        vehicle = Vehicle(
            license_plate=license_plate,
            owner_name=owner_name,
            owner_phone=owner_phone,
            flat_unit_number=flat_unit_number,
            vehicle_type=vehicle_type,
            status=status,
            is_resident=is_resident,
            notes=notes
        )
        
        db.session.add(vehicle)
        db.session.commit()
        
        flash(f'Vehicle {license_plate} added successfully', 'success')
        logging.info(f"User {current_user.username} added vehicle: {license_plate}")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding vehicle: {str(e)}', 'danger')
        logging.error(f"Error adding vehicle: {str(e)}")
    
    return secure_redirect('dashboard.vehicles')

@dashboard_bp.route('/edit_vehicle', methods=['POST'])
@login_required
def edit_vehicle():
    """Edit an existing vehicle"""
    try:
        # Get form data
        vehicle_id = request.form.get('vehicle_id')
        license_plate = request.form.get('license_plate')
        owner_name = request.form.get('owner_name')
        owner_phone = request.form.get('owner_phone')
        flat_unit_number = request.form.get('flat_unit_number')
        vehicle_type = request.form.get('vehicle_type')
        status = request.form.get('status')
        is_resident = True if request.form.get('is_resident') else False
        notes = request.form.get('notes')
        
        # Validate required fields
        if not vehicle_id or not license_plate:
            flash('Vehicle ID and license plate are required', 'danger')
            return secure_redirect('dashboard.vehicles')
            
        # Get vehicle by ID - make sure to convert to int
        try:
            vehicle = Vehicle.query.get(int(vehicle_id))
        except ValueError:
            flash('Invalid vehicle ID', 'danger')
            return secure_redirect('dashboard.vehicles')
            
        if not vehicle:
            flash('Vehicle not found', 'danger')
            return secure_redirect('dashboard.vehicles')
        
        # Check if license plate is already taken by another vehicle (case insensitive)
        if license_plate != vehicle.license_plate:
            # Use the _license_plate column and uppercase the input for case-insensitive comparison
            existing_vehicle = Vehicle.query.filter(
                Vehicle._license_plate == license_plate.upper(),
                Vehicle.id != int(vehicle_id)
            ).first()
            if existing_vehicle:
                flash(f'License plate {license_plate} is already in use', 'danger')
                return secure_redirect('dashboard.vehicles')
        
        # Log values for debugging
        logging.debug(f"Updating vehicle {vehicle_id}: license_plate={license_plate}, owner_name={owner_name}")
        
        # Update vehicle details
        vehicle.license_plate = license_plate
        vehicle.owner_name = owner_name
        vehicle.owner_phone = owner_phone
        vehicle.flat_unit_number = flat_unit_number
        vehicle.vehicle_type = vehicle_type
        vehicle.status = status
        vehicle.is_resident = is_resident
        vehicle.notes = notes
        vehicle.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Vehicle {license_plate} updated successfully', 'success')
        logging.info(f"User {current_user.username} updated vehicle: {license_plate}")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating vehicle: {str(e)}', 'danger')
        logging.error(f"Error updating vehicle: {str(e)}")
    
    return secure_redirect('dashboard.vehicles')

@dashboard_bp.route('/delete_vehicle', methods=['POST'])
@login_required
def delete_vehicle():
    """Delete a vehicle"""
    try:
        # Get vehicle ID from form
        vehicle_id = request.form.get('vehicle_id')
        
        # Validate vehicle ID
        if not vehicle_id:
            flash('Vehicle ID is required', 'danger')
            return secure_redirect('dashboard.vehicles')
            
        # Get vehicle by ID - make sure to convert to int
        try:
            vehicle = Vehicle.query.get(int(vehicle_id))
        except ValueError:
            flash('Invalid vehicle ID', 'danger')
            return secure_redirect('dashboard.vehicles')
            
        if not vehicle:
            flash('Vehicle not found', 'danger')
            return secure_redirect('dashboard.vehicles')
        
        # Store license plate for logging
        license_plate = vehicle.license_plate
        
        # Log deletion attempt
        logging.debug(f"Attempting to delete vehicle ID {vehicle_id}: {license_plate}")
        
        # Delete vehicle
        db.session.delete(vehicle)
        db.session.commit()
        
        flash(f'Vehicle {license_plate} deleted successfully', 'success')
        logging.info(f"User {current_user.username} deleted vehicle: {license_plate}")
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting vehicle: {str(e)}', 'danger')
        logging.error(f"Error deleting vehicle: {str(e)}")
    
    return secure_redirect('dashboard.vehicles')

@dashboard_bp.route('/logs')
@login_required
def logs():
    """Logs page"""
    # Get filter parameters
    search = request.args.get('search', '')
    event_type = request.args.get('event_type', '')
    status = request.args.get('status', '')
    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Parse dates if provided
    start_date = None
    end_date = None
    
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid start date format', 'danger')
    
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid end date format', 'danger')
    
    # Build query based on filters
    query = Log.query
    
    if search:
        # Convert search to uppercase to match license plate format
        query = query.filter(Log.license_plate.ilike(f'%{search.upper()}%'))
    
    if event_type:
        query = query.filter(Log.event_type == event_type)
    
    if status:
        query = query.filter(Log.status == status)
    
    if start_date:
        start_datetime = datetime.combine(start_date, datetime.min.time())
        query = query.filter(Log.timestamp >= start_datetime)
    
    if end_date:
        end_datetime = datetime.combine(end_date, datetime.max.time())
        query = query.filter(Log.timestamp <= end_datetime)
    
    # Order by timestamp, newest first
    query = query.order_by(Log.timestamp.desc())
    
    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items
    
    # Include relevant vehicles information
    vehicles_dict = {}
    vehicle_ids = [log.vehicle_id for log in logs if log.vehicle_id]
    if vehicle_ids:
        vehicles = Vehicle.query.filter(Vehicle.id.in_(vehicle_ids)).all()
        for vehicle in vehicles:
            vehicles_dict[vehicle.id] = vehicle
    
    return render_template(
        'logs.html',
        logs=logs,
        vehicles=vehicles_dict,
        pagination=pagination,
        search=search,
        event_type=event_type,
        status=status,
        start_date=start_date_str,
        end_date=end_date_str,
        current_date=datetime.now().strftime('%Y-%m-%d'),
        current_year=datetime.now().year,
        utils=utils  # Pass the utils module to the template
    )

@dashboard_bp.route('/vehicle_logs/<int:vehicle_id>')
@login_required
def vehicle_logs(vehicle_id):
    """Logs for a specific vehicle"""
    # Get vehicle
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    
    # Get filter parameters
    event_type = request.args.get('event_type', '')
    status = request.args.get('status', '')
    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Parse dates if provided
    start_date = None
    end_date = None
    
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid start date format', 'danger')
    
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Invalid end date format', 'danger')
    
    # Build query based on filters
    query = Log.query.filter(Log.vehicle_id == vehicle_id)
    
    if event_type:
        query = query.filter(Log.event_type == event_type)
    
    if status:
        query = query.filter(Log.status == status)
    
    if start_date:
        start_datetime = datetime.combine(start_date, datetime.min.time())
        query = query.filter(Log.timestamp >= start_datetime)
    
    if end_date:
        end_datetime = datetime.combine(end_date, datetime.max.time())
        query = query.filter(Log.timestamp <= end_datetime)
    
    # Order by timestamp, newest first
    query = query.order_by(Log.timestamp.desc())
    
    # Paginate results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items
    
    return render_template(
        'vehicle_logs.html',
        vehicle=vehicle,
        logs=logs,
        pagination=pagination,
        event_type=event_type,
        status=status,
        start_date=start_date_str,
        end_date=end_date_str,
        Log=Log,  # Pass the Log model to the template
        current_date=datetime.now().strftime('%Y-%m-%d'),
        current_year=datetime.now().year,
        utils=utils  # Pass the utils module to the template
    )

@dashboard_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """System settings page"""
    if not current_user.is_admin:
        flash('You do not have permission to access settings', 'danger')
        return secure_redirect('dashboard.index')
    
    if request.method == 'POST':
        try:
            # Get config instance
            config = current_app.config.get('SYSTEM_CONFIG')
            if not config:
                flash('System configuration not found', 'danger')
                return secure_redirect('dashboard.settings')
            
            # Camera settings
            resolution_w = request.form.get('camera_resolution_width', type=int)
            resolution_h = request.form.get('camera_resolution_height', type=int)
            if resolution_w and resolution_h:
                config.update_setting('camera.resolution', [resolution_w, resolution_h])
            
            framerate = request.form.get('camera_framerate', type=int)
            if framerate:
                config.update_setting('camera.framerate', framerate)
            
            rotation = request.form.get('camera_rotation', type=int)
            if rotation is not None:
                config.update_setting('camera.rotation', rotation)
            
            continuous_capture = True if request.form.get('continuous_capture') else False
            config.update_setting('camera.continuous_capture', continuous_capture)
            
            max_image_width = request.form.get('max_image_width', type=int)
            if max_image_width:
                config.update_setting('camera.max_image_width', max_image_width)
            
            enhance_contrast = True if request.form.get('enhance_contrast') else False
            config.update_setting('camera.enhance_contrast', enhance_contrast)
            
            # ANPR settings
            processing_interval = request.form.get('processing_interval', type=float)
            if processing_interval:
                config.update_setting('anpr.processing_interval', processing_interval)
            
            confidence_threshold = request.form.get('confidence_threshold', type=float)
            if confidence_threshold:
                config.update_setting('anpr.confidence_threshold', confidence_threshold)
            
            auto_register_vehicles = True if request.form.get('auto_register_vehicles') else False
            config.update_setting('anpr.auto_register_vehicles', auto_register_vehicles)
            
            # MyGate API settings
            community_id = request.form.get('community_id')
            if community_id:
                config.update_setting('mygate.community_id', community_id)
            
            device_id = request.form.get('device_id')
            if device_id:
                config.update_setting('mygate.device_id', device_id)
            
            entry_point_name = request.form.get('entry_point_name')
            if entry_point_name:
                config.update_setting('mygate.entry_point_name', entry_point_name)
            
            # System settings
            debug_mode = True if request.form.get('debug_mode') else False
            config.update_setting('system.debug_mode', debug_mode)
            
            log_level = request.form.get('log_level')
            if log_level:
                config.update_setting('system.log_level', log_level)
            
            image_retention_days = request.form.get('image_retention_days', type=int)
            if image_retention_days is not None:
                config.update_setting('system.image_retention_days', image_retention_days)
            
            flash('Settings updated successfully', 'success')
            logging.info(f"System settings updated by user {current_user.username}")
            
            # Check if camera needs to be reinitialized
            camera_settings_changed = any([
                request.form.get('camera_resolution_width'),
                request.form.get('camera_resolution_height'),
                request.form.get('camera_framerate'),
                request.form.get('camera_rotation')
            ])
            
            if camera_settings_changed and camera_manager:
                # Stop current camera
                camera_manager.cleanup()
                # Reinitialize with new settings
                camera_manager.initialize_camera()
                flash('Camera reinitialized with new settings', 'info')
            
            # Check if ANPR processor needs to be updated
            anpr_settings_changed = any([
                request.form.get('processing_interval'),
                request.form.get('confidence_threshold')
            ])
            
            if anpr_settings_changed and anpr_processor and anpr_processor.processing:
                # Restart ANPR processor
                anpr_processor.stop_processing()
                # Wait a moment for processing to stop
                import time
                time.sleep(1)
                # Start with new settings
                anpr_thread = threading.Thread(target=anpr_processor.start_processing)
                anpr_thread.daemon = True
                anpr_thread.start()
                flash('ANPR processor restarted with new settings', 'info')
            
        except Exception as e:
            flash(f'Error updating settings: {str(e)}', 'danger')
            logging.error(f"Error updating settings: {str(e)}")
    
    # Get current settings
    try:
        all_settings = Setting.query.all()
        settings_dict = {setting.key: {
            'value': setting.value,
            'type': setting.type
        } for setting in all_settings}
        
        # Get current environment variables
        env_vars = {
            'PLATE_RECOGNIZER_API_KEY': os.environ.get('PLATE_RECOGNIZER_API_KEY', ''),
            'MYGATE_API_KEY': os.environ.get('MYGATE_API_KEY', ''),
            'MYGATE_API_URL': os.environ.get('MYGATE_API_URL', '')
        }
        
        # Mask API keys for display
        for key in env_vars:
            if env_vars[key] and 'API_KEY' in key:
                env_vars[key] = env_vars[key][:4] + '***' + env_vars[key][-4:] if len(env_vars[key]) > 8 else '***'
        
        # Get config instance
        config = current_app.config.get('SYSTEM_CONFIG')
        
    except Exception as e:
        flash(f'Error loading settings: {str(e)}', 'danger')
        logging.error(f"Error loading settings: {str(e)}")
        settings_dict = {}
        env_vars = {}
        config = None
    
    return render_template(
        'settings.html',
        settings=settings_dict,
        env_vars=env_vars,
        config=config,
        current_year=datetime.now().year
    )
