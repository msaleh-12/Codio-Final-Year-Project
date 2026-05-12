"""
WSGI entrypoint for production servers (gunicorn).
This imports the application factory and creates the app instance.
"""
from run import create_app


app = create_app()
