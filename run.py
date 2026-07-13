import sys
import os
import logging

# Configure logging so you can see exactly what's happening
# in the terminal as jobs come in
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# Tell Python to look for modules from the root folder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dashboard.app import create_app
from pipeline.orchestrator import pipeline_bp
from pipeline.worker import start_worker

# Create the Flask app
app = create_app()

# Register the pipeline blueprint
# This adds the /webhook route to our existing Flask app
app.register_blueprint(pipeline_bp)

# Start the background worker thread
# This runs alongside Flask, checking the queue constantly
start_worker(app)

if __name__ == '__main__':
    print("\n" + "="*50)
    print("  DevGuard Pipeline Starting...")
    print("  Dashboard:  http://127.0.0.1:5000")
    print("  Webhook:    http://127.0.0.1:5000/webhook")
    print("  Status:     http://127.0.0.1:5000/webhook/status")
    print("="*50 + "\n")

    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)