import logging
from app import create_app

# Set up logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create the Flask application
app = create_app()

if __name__ == "__main__":
    # Run the Flask application
    app.run(host="0.0.0.0", port=5000, debug=True)
