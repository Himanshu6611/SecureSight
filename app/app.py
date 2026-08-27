# flask entry
#!/usr/bin/env python3
"""
app/app.py
----------
Run the Flask web server.
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # Debug mode for local development only
    app.run(host="0.0.0.0", port=5000, debug=True)

