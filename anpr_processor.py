import os
import cv2
import logging
import requests
import time
import threading
import json
from datetime import datetime
from models import Vehicle, Log
from app import db
from mygate_api import MyGateAPI

class ANPRProcessor:
    def __init__(self, config, camera_manager):
        self.config = config
        self.camera_manager = camera_manager
        self.plate_recognizer_api_key = os.environ.get("PLATE_RECOGNIZER_API_KEY", "")
        self.plate_recognizer_url = "https://api.platerecognizer.com/v1/plate-reader/"
        self.processing = False
        self.mygate_api = MyGateAPI(config)
        self.lock = threading.Lock()
        self.last_processed_plates = {}  # Store last processed plates with timestamps
        self.processing_interval = self.config.get_processing_interval()  # seconds
        
        # Create directories for storing images if they don't exist
        self.images_dir = "static/images/captures"
        os.makedirs(self.images_dir, exist_ok=True)
        
    def start_processing(self):
        """Start the ANPR processing loop"""
        self.processing = True
        logging.info("Starting ANPR processing")
        
        while self.processing:
            try:
                # Capture image from camera
                image = self.camera_manager.capture_image()
                if image is None:
                    logging.warning("Failed to capture image from camera")
                    time.sleep(2)
                    continue
                
                # Process the image to detect license plates
                plates = self.recognize_plate(image)
                
                if plates:
                    for plate_info in plates:
                        self.process_detected_plate(plate_info, image)
                        
                # Sleep for the configured interval
                time.sleep(self.processing_interval)
                
            except Exception as e:
                logging.error(f"Error in ANPR processing: {str(e)}")
                time.sleep(5)  # Wait a bit longer if there's an error
    
    def stop_processing(self):
        """Stop the ANPR processing loop"""
        self.processing = False
        logging.info("Stopping ANPR processing")
    
    def recognize_plate(self, image):
        """Use Plate Recognizer API to detect license plates in the image"""
        if not self.plate_recognizer_api_key:
            logging.error("Plate Recognizer API key not set")
            return []
            
        try:
            # Save image to a temporary file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            temp_image_path = f"{self.images_dir}/temp_{timestamp}.jpg"
            cv2.imwrite(temp_image_path, image)
            
            # Send image to Plate Recognizer API
            with open(temp_image_path, 'rb') as image_file:
                response = requests.post(
                    self.plate_recognizer_url,
                    files=dict(upload=image_file),
                    headers={'Authorization': f'Token {self.plate_recognizer_api_key}'}
                )
            
            # Process the response
            if response.status_code == 200:
                result = response.json()
                plates = []
                
                if 'results' in result and result['results']:
                    for plate_result in result['results']:
                        plate_info = {
                            'plate': plate_result['plate'],
                            'confidence': plate_result['score'],
                            'box': plate_result['box'],
                            'region': plate_result.get('region', {}).get('code', ''),
                            'vehicle_type': plate_result.get('vehicle', {}).get('type', '')
                        }
                        plates.append(plate_info)
                
                return plates
            else:
                logging.error(f"Plate Recognizer API error: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            logging.error(f"Error recognizing plate: {str(e)}")
            return []
            
    def process_detected_plate(self, plate_info, image):
        """Process a detected license plate"""
        plate_number = plate_info['plate']
        confidence = plate_info['confidence']
        
        # Check if we've recently processed this plate (avoid duplicates)
        current_time = time.time()
        if plate_number in self.last_processed_plates:
            last_time = self.last_processed_plates[plate_number]
            # If processed in the last minute, skip
            if current_time - last_time < 60:
                logging.info(f"Skipping recently processed plate: {plate_number}")
                return
        
        # Update the last processed time for this plate
        self.last_processed_plates[plate_number] = current_time
        
        # Log the detection
        logging.info(f"Detected license plate: {plate_number} with confidence: {confidence}")
        
        # Save the image with the plate highlighted
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_path = f"{self.images_dir}/{plate_number}_{timestamp}.jpg"
        
        # Draw bounding box around the plate
        box = plate_info['box']
        cv2.rectangle(
            image, 
            (box['xmin'], box['ymin']), 
            (box['xmin'] + box['width'], box['ymin'] + box['height']), 
            (0, 255, 0), 
            2
        )
        
        # Add text with plate number
        cv2.putText(
            image, 
            plate_number, 
            (box['xmin'], box['ymin'] - 10), 
            cv2.FONT_HERSHEY_SIMPLEX, 
            0.9, 
            (0, 255, 0), 
            2
        )
        
        # Save the annotated image
        cv2.imwrite(image_path, image)
        
        # Process the vehicle entry/exit
        self.process_vehicle_event(plate_number, confidence, image_path)
    
    def process_vehicle_event(self, plate_number, confidence, image_path):
        """Process a vehicle entry/exit event"""
        with self.lock:
            try:
                # Check if vehicle exists in database
                vehicle = Vehicle.query.filter_by(license_plate=plate_number).first()
                
                # Determine if this is an entry or exit event based on config or previous logs
                event_type = self.determine_event_type(plate_number)
                
                # Create log entry
                log = Log(
                    license_plate=plate_number,
                    confidence=confidence,
                    image_path=image_path,
                    event_type=event_type,
                    status='pending'
                )
                
                if vehicle:
                    log.vehicle_id = vehicle.id
                
                db.session.add(log)
                db.session.commit()
                
                # Process with MyGate API
                mygate_response = None
                try:
                    if event_type == 'entry':
                        mygate_response = self.mygate_api.register_entry(plate_number, vehicle.owner_name if vehicle else None)
                    else:
                        mygate_response = self.mygate_api.register_exit(plate_number)
                    
                    # Update log with MyGate response
                    log.processed_by_mygate = True
                    log.mygate_response = json.dumps(mygate_response)
                    log.status = 'success'
                    
                except Exception as e:
                    log.status = 'error'
                    log.error_message = str(e)
                    logging.error(f"Error processing with MyGate API: {str(e)}")
                
                # If vehicle doesn't exist, create it
                if not vehicle and self.config.get_auto_register_vehicles():
                    vehicle = Vehicle(
                        license_plate=plate_number,
                        status='active',
                        is_resident=False,
                        notes=f'Auto-registered by ANPR system on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
                    )
                    db.session.add(vehicle)
                
                db.session.commit()
                
            except Exception as e:
                db.session.rollback()
                logging.error(f"Error processing vehicle event: {str(e)}")
    
    def determine_event_type(self, plate_number):
        """Determine if this is an entry or exit event"""
        # Get the last log for this plate
        last_log = Log.query.filter_by(license_plate=plate_number).order_by(Log.timestamp.desc()).first()
        
        # If no previous log or last event was exit, this is an entry
        if not last_log or last_log.event_type == 'exit':
            return 'entry'
        # If last event was entry, this is an exit
        else:
            return 'exit'
