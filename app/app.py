# Source Generated with Decompyle++
# File: app/__pycache__/app.cpython-312.pyc (Python 3.12)

'''
app/app.py
----------
Run the Flask web server.
'''
from app import create_app
app = create_app()
if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 5000, debug = True)
    return None
