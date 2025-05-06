# ANPR System - Raspberry Pi Installation Guide

## Project Overview
This Automatic Number Plate Recognition (ANPR) system is designed to run on a Raspberry Pi with a camera module. It captures images, recognizes license plates, and manages vehicle access with integration to MyGate API.

## System Requirements
- Raspberry Pi 4 (recommended) or Raspberry Pi 3B+
- Raspberry Pi Camera Module or compatible USB camera
- Raspbian OS (Buster or newer)
- Python 3.7+ installed
- Internet connection for API services

## Installation Steps

### 1. Prepare your Raspberry Pi
```bash
# Update the system packages
sudo apt update
sudo apt upgrade -y

# Install required system dependencies
sudo apt install -y \
    python3-pip \
    python3-dev \
    libpq-dev \
    postgresql \
    postgresql-contrib \
    libopencv-dev \
    python3-opencv
```

### 2. Set up the Database
```bash
# Create a PostgreSQL database for the application
sudo -u postgres psql -c "CREATE USER anpr_user WITH PASSWORD 'your_secure_password';"
sudo -u postgres psql -c "CREATE DATABASE anpr_db OWNER anpr_user;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE anpr_db TO anpr_user;"
```

### 3. Clone or Extract the Project
```bash
# Create a directory for the project
mkdir -p ~/anpr_system
cd ~/anpr_system

# Extract the project files
unzip /path/to/anpr_system.zip -d .
```

### 4. Install Python Dependencies
```bash
# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install required Python packages
pip install flask \
    flask-sqlalchemy \
    flask-login \
    flask-wtf \
    flask-session \
    gunicorn \
    psycopg2-binary \
    opencv-python \
    Pillow \
    requests \
    email-validator
```

### 5. Configure the Application

```bash
# Edit the config.json file with your settings
nano config.json

# Update the database connection string in the code
nano app.py
# Look for the line with app.config["SQLALCHEMY_DATABASE_URI"] and update it to:
# postgresql://anpr_user:your_secure_password@localhost/anpr_db
```

### 6. Initialize the Database
```bash
python migrate_db.py
```

### 7. Run the Application
```bash
# For development testing
python run_dev.py

# For production deployment
gunicorn --bind 0.0.0.0:5000 main:app
```

### 8. Access the Web Interface
Open a web browser and navigate to `http://raspberry_pi_ip_address:5000`

Default login credentials:
- Username: admin
- Password: admin123

**Important:** Change the default password immediately after the first login!

## Setting up as a Service

To run the ANPR system as a service that starts automatically on boot:

```bash
# Create a systemd service file
sudo nano /etc/systemd/system/anpr.service
```

Add the following content (adjust paths as needed):

```
[Unit]
Description=ANPR System
After=network.target postgresql.service

[Service]
User=pi
WorkingDirectory=/home/pi/anpr_system
Environment="PATH=/home/pi/anpr_system/venv/bin"
ExecStart=/home/pi/anpr_system/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 main:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable anpr.service
sudo systemctl start anpr.service
```

Check status:

```bash
sudo systemctl status anpr.service
```

## Troubleshooting

### Camera Issues
If using the Raspberry Pi Camera Module:
- Ensure the camera is enabled: `sudo raspi-config` → Interface Options → Camera
- Check if the camera works: `libcamera-still -o test.jpg`

If using a USB camera:
- Test with: `v4l2-ctl --list-devices`
- Adjust the camera device in `camera_manager.py`

### Database Connection Issues
- Check PostgreSQL service: `sudo systemctl status postgresql`
- Verify connection details in app.py

### Permissions
- Ensure the application has write access to the static/images/captures directory:
  `sudo chown -R pi:pi ~/anpr_system`

## Known Issues and Next Steps

1. Token-based authentication still has issues when navigating to the vehicles page - this will be fixed in the next update
2. Integration with hardware GPIO pins for gate control needs to be configured based on your specific hardware setup
3. MyGate API integration requires valid API credentials to be configured

## Contact
For support or questions, please contact the developer.
