import cv2
import logging
import time
import threading
import os
from picamera2 import Picamera2

class CameraManager:
    def __init__(self, config):
        self.config = config
        self.camera = None
        self.last_image = None
        self.lock = threading.Lock()
        self.initialized = False
        self.continuous_capture = False
        self.capture_thread = None
        
        # Try to initialize the camera
        self.initialize_camera()
    
    def initialize_camera(self):
        """Initialize the Raspberry Pi camera"""
        try:
            # Initialize PiCamera2
            self.camera = Picamera2()
            
            # Configure the camera
            config = self.camera.create_still_configuration(
                main={"size": (1920, 1080)},
                lores={"size": (640, 480)},
                display="lores"
            )
            self.camera.configure(config)
            
            # Start the camera
            self.camera.start()
            
            # Allow the camera to warm up
            time.sleep(2)
            
            self.initialized = True
            logging.info("Camera initialized successfully")
            
            # Start continuous capture if enabled in config
            if self.config.get_continuous_capture():
                self.start_continuous_capture()
                
        except Exception as e:
            self.initialized = False
            logging.error(f"Failed to initialize camera: {str(e)}")
    
    def capture_image(self):
        """Capture a single image from the camera"""
        with self.lock:
            if not self.initialized:
                logging.warning("Camera not initialized, attempting to reinitialize")
                self.initialize_camera()
                if not self.initialized:
                    return None
            
            try:
                # If continuous capture is enabled, return the last captured image
                if self.continuous_capture and self.last_image is not None:
                    return self.last_image.copy()
                
                # Otherwise, capture a new image
                image = self.camera.capture_array()
                
                # Convert to BGR format if necessary (picamera2 returns RGB)
                if len(image.shape) == 3 and image.shape[2] == 3:
                    image = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
                
                # Apply any image processing if needed
                image = self.process_image(image)
                
                return image
            
            except Exception as e:
                logging.error(f"Error capturing image: {str(e)}")
                # Reset camera if there's an error
                self.initialized = False
                return None
    
    def process_image(self, image):
        """Apply image processing to improve ANPR results"""
        try:
            # Resize if needed
            max_width = self.config.get_max_image_width()
            if max_width > 0 and image.shape[1] > max_width:
                ratio = max_width / image.shape[1]
                new_height = int(image.shape[0] * ratio)
                image = cv2.resize(image, (max_width, new_height))
            
            # Apply any other processing based on config
            if self.config.get_enhance_contrast():
                # Convert to LAB color space
                lab = cv2.cvtColor(image, cv2.COLOR_BGR2LAB)
                # Split the LAB image into L, A, and B channels
                l, a, b = cv2.split(lab)
                # Apply CLAHE to L channel
                clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
                cl = clahe.apply(l)
                # Merge the enhanced L channel with A and B channels
                updated_lab = cv2.merge((cl, a, b))
                # Convert LAB back to BGR
                image = cv2.cvtColor(updated_lab, cv2.COLOR_LAB2BGR)
            
            return image
            
        except Exception as e:
            logging.error(f"Error processing image: {str(e)}")
            return image  # Return original image if processing fails
    
    def start_continuous_capture(self):
        """Start continuous image capture in a separate thread"""
        if self.continuous_capture:
            return
        
        self.continuous_capture = True
        self.capture_thread = threading.Thread(target=self._continuous_capture_thread)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        logging.info("Started continuous image capture")
    
    def stop_continuous_capture(self):
        """Stop continuous image capture"""
        self.continuous_capture = False
        if self.capture_thread:
            self.capture_thread.join(timeout=1.0)
            self.capture_thread = None
        logging.info("Stopped continuous image capture")
    
    def _continuous_capture_thread(self):
        """Thread function for continuous image capture"""
        while self.continuous_capture:
            try:
                with self.lock:
                    if self.initialized:
                        image = self.camera.capture_array()
                        # Convert to BGR format if necessary
                        if len(image.shape) == 3 and image.shape[2] == 3:
                            image = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
                        
                        # Process the image
                        image = self.process_image(image)
                        
                        # Update the last image
                        self.last_image = image
            
            except Exception as e:
                logging.error(f"Error in continuous capture: {str(e)}")
                self.initialized = False
                # Try to reinitialize
                self.initialize_camera()
            
            # Sleep for a short period between captures
            time.sleep(0.1)
    
    def cleanup(self):
        """Clean up camera resources"""
        self.stop_continuous_capture()
        
        with self.lock:
            if self.initialized and self.camera:
                try:
                    self.camera.stop()
                    self.camera.close()
                except Exception as e:
                    logging.error(f"Error closing camera: {str(e)}")
                finally:
                    self.camera = None
                    self.initialized = False
