"""
Generate sample log entries for existing vehicles.
This script will create entry and exit events for vehicles in the database.
"""

import os
import sys
import random
from datetime import datetime, timedelta

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import db
from models import Vehicle, Log

def generate_sample_logs(num_entries=20):
    """Generate sample log entries for existing vehicles."""
    print(f"Generating {num_entries} sample log entries...")
    
    # Get all vehicles
    vehicles = Vehicle.query.all()
    
    if not vehicles:
        print("No vehicles found in the database. Please add vehicles first.")
        return
    
    # Sample image paths
    sample_images = [
        "static/images/captures/sample1.jpg",
        "static/images/captures/sample2.jpg",
        "static/images/captures/sample3.jpg",
        None  # Sometimes no image
    ]
    
    # Event types
    event_types = ["entry", "exit"]
    
    # Status options
    statuses = ["success", "error", "pending"]
    
    # Error messages for error status
    error_messages = [
        "Failed to process with MyGate API",
        "Low confidence detection",
        "Vehicle not registered",
        "Connection timeout",
        None  # Sometimes no error message even for errors
    ]
    
    # Generate logs over the past week
    now = datetime.utcnow()
    earliest_date = now - timedelta(days=7)
    
    count = 0
    for _ in range(num_entries):
        # Select a random vehicle
        vehicle = random.choice(vehicles)
        
        # Generate a random timestamp within the past week
        random_seconds = random.randint(0, int((now - earliest_date).total_seconds()))
        timestamp = earliest_date + timedelta(seconds=random_seconds)
        
        # Select random event type
        event_type = random.choice(event_types)
        
        # Generate random confidence score (60-100)
        confidence = random.uniform(60.0, 100.0)
        
        # Select random status (mostly success)
        status = random.choices(
            statuses,
            weights=[0.8, 0.15, 0.05],  # 80% success, 15% error, 5% pending
            k=1
        )[0]
        
        # Determine error message if status is error
        error_message = None
        if status == "error":
            error_message = random.choice(error_messages)
        
        # Select random image path (sometimes None)
        image_path = random.choice(sample_images)
        
        # Create log entry
        log = Log(
            vehicle_id=vehicle.id,
            license_plate=vehicle.license_plate,
            confidence=confidence,
            timestamp=timestamp,
            image_path=image_path,
            event_type=event_type,
            processed_by_mygate=status == "success",
            status=status,
            error_message=error_message
        )
        
        db.session.add(log)
        count += 1
    
    # Commit all entries to the database
    try:
        db.session.commit()
        print(f"Successfully added {count} log entries.")
    except Exception as e:
        db.session.rollback()
        print(f"Error adding log entries: {str(e)}")

if __name__ == "__main__":
    # Create directory for sample images if it doesn't exist
    os.makedirs("static/images/captures", exist_ok=True)
    
    # Determine number of entries to generate from command line arg or default
    num_entries = 20
    if len(sys.argv) > 1:
        try:
            num_entries = int(sys.argv[1])
        except ValueError:
            print(f"Invalid number of entries: {sys.argv[1]}. Using default: 20")
    
    # Get the Flask app and run within application context
    from app import create_app
    app = create_app()
    
    with app.app_context():
        # Generate log entries
        generate_sample_logs(num_entries)