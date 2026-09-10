import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app import create_app

app = create_app(os.environ.get('FLASK_ENV', 'dev'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
