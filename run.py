import sys
import os

# This line tells Python to look for modules 
# from the root Dev-Guard folder, not from inside dashboard/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dashboard.app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)