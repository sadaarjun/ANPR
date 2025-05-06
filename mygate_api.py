import requests
import json
import logging
import os
from datetime import datetime

class MyGateAPI:
    def __init__(self, config):
        self.config = config
        self.api_key = os.environ.get("MYGATE_API_KEY", "")
        self.api_base_url = os.environ.get("MYGATE_API_URL", "https://api.mygate.com/v1")
        self.community_id = self.config.get_community_id()
        self.device_id = self.config.get_device_id()
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
    
    def register_entry(self, license_plate, owner_name=None):
        """Register a vehicle entry with MyGate API"""
        if not self.api_key:
            logging.error("MyGate API key not set")
            raise ValueError("MyGate API key not set")
        
        # Endpoint for vehicle entry
        endpoint = f"{self.api_base_url}/communities/{self.community_id}/vehicles/entry"
        
        # Prepare data payload
        payload = {
            "license_plate": license_plate,
            "timestamp": datetime.now().isoformat(),
            "device_id": self.device_id,
            "entry_point": self.config.get_entry_point_name()
        }
        
        # Add owner name if available
        if owner_name:
            payload["owner_name"] = owner_name
        
        # Send the request
        try:
            response = requests.post(endpoint, headers=self.headers, json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error registering entry with MyGate API: {str(e)}")
            if hasattr(e, 'response') and e.response:
                logging.error(f"Response: {e.response.text}")
            raise
    
    def register_exit(self, license_plate):
        """Register a vehicle exit with MyGate API"""
        if not self.api_key:
            logging.error("MyGate API key not set")
            raise ValueError("MyGate API key not set")
        
        # Endpoint for vehicle exit
        endpoint = f"{self.api_base_url}/communities/{self.community_id}/vehicles/exit"
        
        # Prepare data payload
        payload = {
            "license_plate": license_plate,
            "timestamp": datetime.now().isoformat(),
            "device_id": self.device_id,
            "exit_point": self.config.get_entry_point_name()  # Usually same as entry point
        }
        
        # Send the request
        try:
            response = requests.post(endpoint, headers=self.headers, json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error registering exit with MyGate API: {str(e)}")
            if hasattr(e, 'response') and e.response:
                logging.error(f"Response: {e.response.text}")
            raise
    
    def get_vehicle_details(self, license_plate):
        """Get vehicle details from MyGate API"""
        if not self.api_key:
            logging.error("MyGate API key not set")
            raise ValueError("MyGate API key not set")
        
        # Endpoint for vehicle details
        endpoint = f"{self.api_base_url}/communities/{self.community_id}/vehicles/{license_plate}"
        
        # Send the request
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error getting vehicle details from MyGate API: {str(e)}")
            if hasattr(e, 'response') and e.response:
                logging.error(f"Response: {e.response.text}")
            raise
    
    def verify_resident_vehicle(self, license_plate):
        """Verify if a vehicle belongs to a resident"""
        if not self.api_key:
            logging.error("MyGate API key not set")
            return False
        
        try:
            vehicle_details = self.get_vehicle_details(license_plate)
            return vehicle_details.get('is_resident', False)
        except:
            return False
    
    def register_visitor(self, name, phone, license_plate=None):
        """Register a visitor with MyGate API"""
        if not self.api_key:
            logging.error("MyGate API key not set")
            raise ValueError("MyGate API key not set")
        
        # Endpoint for visitor registration
        endpoint = f"{self.api_base_url}/communities/{self.community_id}/visitors"
        
        # Prepare data payload
        payload = {
            "name": name,
            "phone": phone,
            "entry_time": datetime.now().isoformat(),
            "device_id": self.device_id,
            "entry_point": self.config.get_entry_point_name()
        }
        
        # Add license plate if available
        if license_plate:
            payload["vehicle"] = {"license_plate": license_plate}
        
        # Send the request
        try:
            response = requests.post(endpoint, headers=self.headers, json=payload)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error registering visitor with MyGate API: {str(e)}")
            if hasattr(e, 'response') and e.response:
                logging.error(f"Response: {e.response.text}")
            raise
