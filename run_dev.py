from app import create_app
import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create the Flask application
app = create_app()

# Run the app with a single worker (for testing session issues)
if __name__ == "__main__":
    # Use a different port (5001) since 5000 is already in use
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=True)
