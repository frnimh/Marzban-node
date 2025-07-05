from decouple import config
from dotenv import load_dotenv

# Load environment variables from a .env file if it exists
load_dotenv()

# Service configuration
SERVICE_HOST = config("SERVICE_HOST", default="0.0.0.0")
SERVICE_PORT = config('SERVICE_PORT', cast=int, default=62050)
SERVICE_PROTOCOL = config('SERVICE_PROTOCOL', cast=str, default='rest')

# Xray core configuration
XRAY_API_HOST = config("XRAY_API_HOST", default="0.0.0.0")
XRAY_API_PORT = config('XRAY_API_PORT', cast=int, default=62051)
XRAY_EXECUTABLE_PATH = config("XRAY_EXECUTABLE_PATH", default="/usr/local/bin/xray")
XRAY_ASSETS_PATH = config("XRAY_ASSETS_PATH", default="/usr/local/share/xray")

# SSL/TLS certificate paths
SSL_CERT_FILE = config("SSL_CERT_FILE", default="/var/lib/marzban-node/ssl_cert.pem")
SSL_KEY_FILE = config("SSL_KEY_FILE", default="/var/lib/marzban-node/ssl_key.pem")
SSL_CLIENT_CERT_FILE = config("SSL_CLIENT_CERT_FILE", default="")

# General settings
DEBUG = config("DEBUG", cast=bool, default=False)
INBOUNDS = config("INBOUNDS", cast=lambda v: [x.strip() for x in v.split(',')] if v else [], default="")
OUTBOUNDS = config("OUTBOUNDS", cast=lambda v: [x.strip() for x in v.split(',')] if v else [], default="")
