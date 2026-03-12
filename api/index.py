"""
SentinelShield — Vercel Serverless Entry Point
Exposes the Flask app as `app` for Vercel's WSGI adapter.
"""

from flask_app.app import app

# Vercel looks for a variable named `app` in this module.
# No other configuration is needed.
