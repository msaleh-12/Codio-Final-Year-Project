"""
Codio Backend - Logging Configuration
"""

import logging


def setup_logging():
    """Configure application-wide logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('api_server.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('codio')
