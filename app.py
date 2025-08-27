from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_compress import Compress
from PIL import Image
import qrcode
import io
import base64
import uuid
from datetime import datetime, timedelta
import os
import json
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
import pandas as pd
from io import BytesIO
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
import secrets
import re
import hashlib
import hmac
import bleach
from collections import defaultdict
import threading

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY'] or len(app.config['SECRET_KEY']) < 16:
    raise ValueError("SECRET_KEY muss gesetzt und mindestens 16 Zeichen lang sein!")

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gaeste.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True, 'pool_recycle': 300}

required_mail_configs = ['MAIL_SERVER', 'MAIL_USERNAME', 'MAIL_PASSWORD']
for config in required_mail_configs:
    if not os.environ.get(config):
        raise ValueError(f"Erforderliche E-Mail-Konfiguration fehlt: {config}")

app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = os.environ.get('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['SESSION_COOKIE_NAME'] = '__Secure-session'
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
app.config['PROPAGATE_EXCEPTIONS'] = False

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
EVENT_PASSWORD = os.environ.get('EVENT_PASSWORD')
if not all([ADMIN_USERNAME, ADMIN_PASSWORD, EVENT_PASSWORD]):
    raise ValueError("ADMIN_USERNAME, ADMIN_PASSWORD und EVENT_PASSWORD müssen gesetzt sein!")

def validate_password_complexity(password):
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[^A-Za-z0-9]', password):
        return False
    return True

if not validate_password_complexity(ADMIN_PASSWORD):
    app.logger.warning("ADMIN_PASSWORD sollte komplexer sein")

ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256:260000')

BERLIN_TZ = pytz.timezone('Europe/Berlin')

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

Compress(app)

csp = {
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline'",
    'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com",
    'font-src': "'self' https://fonts.gstatic.com",
    'img-src': "'self' data: https:",
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
    'base-uri': "'self'",
    'form-action': "'self'",
}

force_https = os.environ.get('FORCE_HTTPS', 'False').lower() == 'true'
if force_https:
    csp['upgrade-insecure-requests'] = []

Talisman(
    app,
    content_security_policy=csp,
    force_https=force_https,
    strict_transport_security=force_https,
    strict_transport_security_max_age=31536000 if force_https else 0,
    force_file_save=True,
    x_content_type_options=True,
    frame_options='DENY',
    x_xss_protection=True,
    referrer_policy='strict-origin-when-cross-origin'
)

limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["100 per day", "30 per hour"], storage_uri='memory://')

db = SQLAlchemy(app)
mail = Mail(app)

class SecurityManager:
    def __init__(self):
        self.failed_attempts = defaultdict(lambda: {'count': 0, 'blocked_until': None})
        self.lock = threading.Lock()
    def is_ip_blocked(self, ip):
        with self.lock:
            data = self.failed_attempts.get(ip)
            if not data:
                return False
            if data['blocked_until'] and datetime.now() > data['blocked_until']:
                self.failed_attempts[ip] = {'count': 0, 'blocked_until': None}
                return False
            return data['count'] >= 5
    def record_failed_attempt(self, ip):
        with self.lock:
            d = self.failed_attempts[ip]
            d['count'] += 1
            if d['count'] >= 5:
                d['blocked_until'] = datetime.now() + timedelta(hours=1)
    def record_success(self, ip):
        with self.lock:
            if ip in self.failed_attempts:
                self.failed_attempts[ip]['count'] = max(0, self.failed_attempts[ip]['count'] - 1)

security_manager = SecurityManager()

def setup_logging():
    if not app.debug:
        os.makedirs('logs', exist_ok=True)
        file_handler = RotatingFileHandler('logs/app.log', maxBytes=10_000_000, backupCount=10)
        file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('App startup')

def get_berlin_time():
    return datetime.now(BERLIN_TZ)

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    return token and 'csrf_token' in session and hmac.compare_digest(token, session['csrf_token'])

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.before_request
def enforce_csrf():
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
        if not token and request.is_json:
            token = (request.json or {}).get('csrf_token')
        if not validate_csrf_token(token):
            abort(400)

def sanitize_input(value, max_length=None):
    if not value:
        return ''
    value = str(value).strip()
    if max_length and len(value) > max_length:
        value = value[:max_length]
    return bleach.clean(value, tags=[], strip=True)

def validate_email(email):
    if not email:
        return False
    email = email.strip().lower()
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) and len(email) <= 254

def validate_phone(phone):
    if not phone:
        return True
    pattern = r'^[\+]?[- 0-9()\/]{8,20}$'
    if not re.match(pattern, phone):
        return False
    digits = re.findall(r'\d', phone)
    return len(digits) >= 8

def validate_name(name):
    if not name or len(name) < 1:
        return False
    pattern = r"^[a-zA-ZäöüÄÖÜßàáâãéêëíîïóôõúûüýÿçñ'\-\s]{1,100}$"
    return re.match(pattern, name) is not None

def validate_plz(plz):
    if not plz:
        return False
    return re.match(r'^\d{5}$', plz) is not None

def regenerate_session():
    old_data = dict(session)
    session.clear()
    session.update(old_data)
    session.permanent = True

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_remote_address()
        if security_manager.is_ip_blocked(client_ip):
            app.logger.warning(f'Blocked IP {client_ip} tried to access admin area')
            flash('Zu viele fehlgeschlagene Login-Versuche. Versuchen Sie es später erneut.', 'error')
            return redirect(url_for('admin_login'))
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def event_password_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_remote_address()
        if security_manager.is_ip_blocked(client_ip):
            flash('Zu viele fehlgeschlagene Versuche. Versuchen Sie es später erneut.', 'error')
            return redirect(url_for('event_login'))
        if not session.get('event_authenticated'):
            return redirect(url_for('event_login'))
        return f(*args, **kwargs)
    return decorated_function

class Gast(db.Model):
    __tablename__ = 'gast'
    id = db.Column(db.Integer, primary_key=True)
    vorname = db.Column(db.String(100), nullable=False, index=True)
    nachname = db.Column(db.String(100), nullable=False, index=True)
    email = db.Column(db.String(100), nullable=False, index=True)
    adresse = db.Column(db.String(200), nullable=False)
    hausnr = db.Column(db.String(10), nullable=False)
    plz = db.Column(db.String(10), nullable=False, index=True)
    ort = db.Column(db.String(100), nullable=False)
    telefon = db.Column(db.String(20), nullable=False)
    berater = db.Column(db.String(100), nullable=True, index=True)
    kinder = db.Column(db.String(20), nullable=False)
    kinder_daten = db.Column(db.Text, nullable=True)
    zustimmung = db.Column(db.String(3), nullable=False)
    nachricht = db.Column(db.Text, nullable=True)
    unique_code = db.Column(db.String(36), unique=True, nullable=False, index=True)
    anwesend = db.Column(db.Boolean, default=False, index=True)
    registriert_am = db.Column(db.DateTime, default=get_berlin_time, index=True)
    anwesenheit_geaendert_am = db.Column(db.DateTime, nullable=True)
    ticket_bestaetigt = db.Column(db.Boolean, default=False, index=True)
    ticket_bestaetigt_am = db.Column(db.DateTime, nullable=True)
    ticket_versendet = db.Column(db.Boolean, default=False)
    ticket_versendet_am = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent_hash = db.Column(db.String(64), nullable=True)
    last_activity = db.Column(db.DateTime, default=get_berlin_time)
    def get_kinder_liste(self):
        if self.kinder_daten:
            try:
                return json.loads(self.kinder_daten)
            except json.JSONDecodeError:
                app.logger.error(f'JSON decode error for guest {self.id}')
                return []
        return []
    def set_kinder_liste(self, kinder_liste):
        self.kinder_daten = json.dumps(kinder_liste, ensure_ascii=False) if kinder_liste else None
    def get_formatted_registriert_am(self):
        if self.registriert_am:
            if self.registriert_am.tzinfo is None:
                berlin_time = BERLIN_TZ.localize(self.registriert_am)
            else:
                berlin_time = self.registriert_am.astimezone(BERLIN_TZ)
            return berlin_time
        return None
    def get_formatted_anwesenheit_geaendert_am(self):
        if self.anwesenheit_geaendert_am:
            if self.anwesenheit_geaendert_am.tzinfo is None:
                berlin_time = BERLIN_TZ.localize(self.anwesenheit_geaendert_am)
            else:
                berlin_time = self.anwesenheit_geaendert_am.astimezone(BERLIN_TZ)
            return berlin_time
        return None
    def __repr__(self):
        return f'<Gast {self.vorname} {self.nachname}>'

class AuditLog(db.Model):
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=get_berlin_time, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500), nullable=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource = db.Column(db.String(100), nullable=True)
    details = db.Column(db.Text, nullable=True)
    success = db.Column(db.Boolean, nullable=False, index=True)
    user_id = db.Column(db.String(100), nullable=True)

def log_security_event(action, resource=None, details=None, success=True, user_id=None):
    try:
        audit_entry = AuditLog(
            ip_address=get_remote_address(),
            user_agent=request.headers.get('User-Agent', '')[:500] if request else '',
            action=action,
            resource=resource,
            details=details,
            success=success,
            user_id=user_id
        )
        db.session.add(audit_entry)
        db.session.commit()
    except Exception as e:
        app.logger.error(f'Failed to log security event: {e}')

def generiere_qr_code(unique_code):
    try:
        base_url = request.url_root
        if force_https and not base_url.startswith('https://'):
            base_url = base_url.replace('http://', 'https://', 1)
        qr_url = f"{base_url}checkin/{unique_code}"
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=5)
        qr.add_data(qr_url)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
        hintergrund_path = os.path.join(app.root_path, "static", "bilder", "ticket_hintergrund.jpg")
        logo_path = os.path.join(app.root_path, "static", "bilder", "sts-logo.png")
        if not os.path.exists(hintergrund_path) or not os.path.exists(logo_path):
            img_buffer = io.BytesIO()
            qr_img.save(img_buffer, format="PNG", optimize=True)
            img_buffer.seek(0)
            return base64.b64encode(img_buffer.getvalue()).decode()
        hintergrund = Image.open(hintergrund_path).convert("RGBA")
        logo = Image.open(logo_path).convert("RGBA")
        max_dimension = 2000
        if hintergrund.width > max_dimension or hintergrund.height > max_dimension:
            hintergrund.thumbnail((max_dimension, max_dimension), Image.LANCZOS)
        if logo.width > max_dimension or logo.height > max_dimension:
            logo.thumbnail((max_dimension, max_dimension), Image.LANCZOS)
        logo_width = int(hintergrund.width * 0.65)
        logo_height = int(logo.height * (logo_width / logo.width))
        logo = logo.resize((logo_width, logo_height), Image.LANCZOS)
        qr_size = int(hintergrund.width * 0.55)
        qr_img = qr_img.resize((qr_size, qr_size), Image.LANCZOS)
        logo_x = (hintergrund.width - logo.width) // 2
        logo_y = int(hintergrund.height * 0.05)
        hintergrund.paste(logo, (logo_x, logo_y), logo)
        qr_x = (hintergrund.width - qr_img.width) // 2
        qr_y = (hintergrund.height - qr_img.height) // 2
        hintergrund.paste(qr_img, (qr_x, qr_y), qr_img)
        img_buffer = io.BytesIO()
        hintergrund.save(img_buffer, format="PNG", optimize=True, compress_level=6)
        img_buffer.seek(0)
        return base64.b64encode(img_buffer.getvalue()).decode()
    except Exception as e:
        app.logger.error(f"QR-Code Generation Error: {str(e)}")
        img_buffer = io.BytesIO()
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img.save(img_buffer, format="PNG")
        img_buffer.seek(0)
        return base64.b64encode(img_buffer.getvalue()).decode()

def sende_registrierung_email(gast):
    try:
        if not validate_email(gast.email):
            app.logger.error(f'Invalid email address: {gast.email}')
            return False
        kinder_liste = gast.get_kinder_liste()
        kinder_text = ""
        if kinder_liste:
            kinder_text = "<h3>Angemeldete Kinder:</h3><ul>" + "".join(
                f"<li>Kind {i}: {sanitize_input(k.get('vorname',''),50)} {sanitize_input(k.get('nachname',''),50)}</li>" for i, k in enumerate(kinder_liste, 1)
            ) + "</ul>"
        msg = Message(subject='Ihre Anmeldung wurde erhalten - Bestätigung folgt', sender=app.config['MAIL_USERNAME'], recipients=[gast.email])
        vorname = sanitize_input(gast.vorname, 100)
        nachname = sanitize_input(gast.nachname, 100)
        email = sanitize_input(gast.email, 100)
        telefon = sanitize_input(gast.telefon, 20)
        kinder = sanitize_input(gast.kinder, 20)
        berater = sanitize_input(gast.berater or 'Nicht angegeben', 100)
        msg.html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50;">Hallo {vorname}!</h2>
                <p>vielen Dank für Ihre Anmeldung zu unserer Halloween-Veranstaltung!</p>
                
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #2c3e50; margin-top: 0;">Ihre Anmeldedaten:</h3>
                    <p><strong>Name:</strong> {vorname} {nachname}</p>
                    <p><strong>E-Mail:</strong> {email}</p>
                    <p><strong>Telefon:</strong> {telefon}</p>
                    <p><strong>Anzahl Kinder:</strong> {kinder}</p>
                    <p><strong>Eingeladen von:</strong> {berater}</p>
                    
                    {kinder_text}
                </div>
                
                <div style="background: #e8f4fd; padding: 15px; border-radius: 8px; border-left: 4px solid #3498db; margin: 20px 0;">
                    <h3 style="color: #1976d2; margin-top: 0;">📧 Nächster Schritt:</h3>
                    <p>Ihre Anmeldung wird nun von unserem Team geprüft. Sie erhalten in Kürze eine weitere E-Mail mit:</p>
                    <ul>
                        <li>✅ Bestätigung Ihrer Teilnahme</li>
                        <li>🎫 Ihrem persönlichen QR-Code-Ticket</li>
                        <li>📋 Weiteren Informationen zur Veranstaltung</li>
                    </ul>
                </div>
                
                <div style="margin: 30px 0; padding: 15px; background: #fff3cd; border-radius: 8px; border-left: 4px solid #ffc107;">
                    <p><strong>⏰ Bitte haben Sie etwas Geduld:</strong><br>
                    Wir bearbeiten alle Anmeldungen manuell, um Ihnen den bestmöglichen Service zu bieten. 
                    Sie hören spätestens innerhalb von 24 Stunden von uns.</p>
                </div>
                
                <hr style="margin: 30px 0; border: 0; height: 1px; background: #e1e5e9;">
                
                <p>Falls Sie Fragen haben, können Sie gerne antworten oder uns direkt kontaktieren.</p>
                
                <p style="margin-top: 30px;">
                    <strong>Ihr Team von STS Schumacher Finanzen & Consulting</strong><br>
                    <small style="color: #666;">
                        📧 info@sts-finanzen.de<br>
                        📞 +49 208 82 84 59 00<br>
                        🌐 www.sts-finanzen.de
                    </small>
                </p>
            </div>
        </body>
        </html>
        """
        mail.send(msg)
        app.logger.info(f'Registrierungs-E-Mail gesendet an {gast.email}')
        return True
    except Exception as e:
        app.logger.error(f"Fehler beim E-Mail-Versand: {str(e)}")
        return False

def sende_ticket_email(gast, qr_code_base64):
    try:
        qr_bytes = base64.b64decode(qr_code_base64)
        kinder_liste = gast.get_kinder_liste()
        kinder_text = ""
        if kinder_liste:
            kinder_text = "<h3>Angemeldete Kinder:</h3><ul>" + "".join(
                f"<li>Kind {i}: {sanitize_input(k.get('vorname',''))} {sanitize_input(k.get('nachname',''))}</li>" for i, k in enumerate(kinder_liste, 1)
            ) + "</ul>"
        msg = Message(subject='Ihre Teilnahme ist bestätigt - QR-Code-Ticket anbei!', sender=app.config['MAIL_USERNAME'], recipients=[gast.email])
        msg.html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50;">🎉 Großartige Neuigkeiten, {sanitize_input(gast.vorname)}!</h2>
                <p>Ihre Anmeldung wurde <strong>bestätigt</strong> und Sie sind offiziell für unsere Halloween-Veranstaltung angemeldet!</p>
                
                <div style="background: #d4edda; padding: 20px; border-radius: 8px; border-left: 4px solid #28a745; margin: 20px 0; text-align: center;">
                    <h3 style="color: #155724; margin-top: 0;">✅ Teilnahme bestätigt!</h3>
                    <p style="margin-bottom: 0; font-size: 16px;">Wir freuen uns auf Sie am <strong>31. Oktober 2025</strong></p>
                </div>
                
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                    <h3 style="color: #2c3e50; margin-top: 0;">Ihre Anmeldedaten:</h3>
                    <p><strong>Name:</strong> {sanitize_input(gast.vorname)} {sanitize_input(gast.nachname)}</p>
                    <p><strong>E-Mail:</strong> {sanitize_input(gast.email)}</p>
                    <p><strong>Telefon:</strong> {sanitize_input(gast.telefon)}</p>
                    <p><strong>Anzahl Kinder:</strong> {sanitize_input(gast.kinder)}</p>
                    <p><strong>Eingeladen von:</strong> {sanitize_input(gast.berater)}</p>
                    
                    {kinder_text}
                </div>
                
                <div style="background: #e8f4fd; padding: 20px; border-radius: 8px; border-left: 4px solid #3498db; margin: 20px 0; text-align: center;">
                    <h3 style="color: #1976d2; margin-top: 0;">🎫 Ihr QR-Code-Ticket</h3>
                    <p>Bitte verwenden Sie den untenstehenden QR-Code für Ihren Check-in:</p>
                    <img src="data:image/png;base64,{qr_code_base64}" alt="QR Code" style="max-width: 300px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
                    
                    <div style="margin-top: 15px; padding: 10px; background: white; border-radius: 4px;">
                        <p style="margin: 5px 0;"><strong>Alternative Check-in URL:</strong></p>
                        <a href="{request.url_root}checkin/{gast.unique_code}" 
                           style="color: #3498db; word-break: break-all; font-size: 14px;">
                           {request.url_root}checkin/{gast.unique_code}
                        </a>
                    </div>
                </div>
                
                <div style="background: #fff3cd; padding: 15px; border-radius: 8px; border-left: 4px solid #ffc107; margin: 20px 0;">
                    <h4 style="color: #856404; margin-top: 0;">📋 Wichtige Hinweise:</h4>
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        <li>Bewahren Sie dieses Ticket sicher auf</li>
                        <li>Der QR-Code ist auch als Datei im Anhang verfügbar</li>
                        <li>Bei Problemen mit dem Check-in nutzen Sie den alternativen Link</li>
                        <li>Bringen Sie gerne Ihr Smartphone mit dem QR-Code mit</li>
                    </ul>
                </div>
                
                <hr style="margin: 30px 0; border: 0; height: 1px; background: #e1e5e9;">
                
                <p><strong>🎃 Wir freuen uns auf eine schaurig-schöne Halloween-Nacht mit Ihnen!</strong></p>
                
                <p style="margin-top: 30px;">
                    <strong>Ihr Team von STS Schumacher Finanzen & Consulting</strong><br>
                    <small style="color: #666;">
                        📧 info@sts-finanzen.de<br>
                        📞 +49 208 82 84 59 00<br>
                        🌐 www.sts-finanzen.de
                    </small>
                </p>
            </div>
        </body>
        </html>
        """
        msg.attach("halloween-ticket.png", "image/png", qr_bytes)
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Fehler beim Ticket-E-Mail-Versand: {str(e)}")
        return False

@app.route('/')
def index():
    if session.get('event_authenticated'):
        return redirect(url_for('landingpage'))
    return render_template('event_login.html')

@app.route('/event-login', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def event_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == EVENT_PASSWORD:
            session['event_authenticated'] = True
            regenerate_session()
            return redirect(url_for('landingpage'))
        else:
            flash('Ungültiges Passwort!', 'error')
            security_manager.record_failed_attempt(get_remote_address())
            log_security_event('event_login_failed', success=False)
    return render_template('event_login.html')

@app.route('/landingpage')
@event_password_required
def landingpage():
    return render_template('landingpage.html')

@app.route('/welcome')
@event_password_required
def welcome():
    return render_template('landingpage.html')

@app.route('/medien')
@event_password_required
def medien():
    return render_template('medien.html')

@app.route('/register', methods=['GET'])
def register():
    return redirect(url_for('event_login'))

@app.route('/register-submit', methods=['POST'])
@event_password_required
@limiter.limit("10 per hour")
def register_submit():
    vorname = sanitize_input(request.form.get('vorname'), 100)
    nachname = sanitize_input(request.form.get('nachname'), 100)
    email = sanitize_input(request.form.get('email'), 100)
    telefon = sanitize_input(request.form.get('telefon', ''), 20)
    adresse = sanitize_input(request.form.get('adresse', ''), 200)
    hausnr = sanitize_input(request.form.get('hausnr', ''), 10)
    plz = sanitize_input(request.form.get('plz', ''), 10)
    ort = sanitize_input(request.form.get('ort', ''), 100)
    berater = sanitize_input(request.form.get('berater', ''), 100)
    kinder = sanitize_input(request.form.get('kinder', '0'), 20)
    zustimmung = sanitize_input(request.form.get('zustimmung'), 3)
    nachricht = sanitize_input(request.form.get('nachricht', ''), 2000)
    if not (validate_name(vorname) and validate_name(nachname) and validate_email(email) and validate_plz(plz) and validate_phone(telefon)):
        return redirect(url_for('landingpage', error='Bitte Eingaben prüfen.'))
    if not kinder:
        kinder = '0'
    kinder_liste = []
    anzahl_kinder = int(kinder) if kinder.isdigit() else 0
    for i in range(1, anzahl_kinder + 1):
        kind_vorname = sanitize_input(request.form.get(f'kind{i}_vorname'), 100)
        kind_nachname = sanitize_input(request.form.get(f'kind{i}_nachname'), 100)
        if not kind_vorname or not kind_nachname:
            return redirect(url_for('landingpage', error=f'Bitte geben Sie Vor- und Nachname für Kind {i} an.'))
        kinder_liste.append({'vorname': kind_vorname, 'nachname': kind_nachname})
    unique_code = str(uuid.uuid4())
    neuer_gast = Gast(
        vorname=vorname,
        nachname=nachname,
        email=email,
        telefon=telefon,
        adresse=adresse,
        hausnr=hausnr,
        plz=plz,
        ort=ort,
        berater=berater,
        kinder=kinder,
        zustimmung=zustimmung,
        nachricht=nachricht,
        unique_code=unique_code,
        registriert_am=get_berlin_time(),
        ticket_bestaetigt=False,
        ticket_versendet=False,
        ip_address=request.remote_addr,
        user_agent_hash=hashlib.sha256((request.headers.get('User-Agent','')).encode()).hexdigest()
    )
    neuer_gast.set_kinder_liste(kinder_liste)
    try:
        db.session.add(neuer_gast)
        db.session.commit()
        email_erfolg = sende_registrierung_email(neuer_gast)
        if email_erfolg:
            return redirect(url_for('success', vorname=vorname, nachname=nachname))
        else:
            return redirect(url_for('landingpage', error='Registrierung erfolgreich, aber E-Mail konnte nicht gesendet werden'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Fehler bei der Registrierung: {str(e)}")
        return redirect(url_for('landingpage', error='Ein Fehler ist aufgetreten'))

@app.route('/datenschutz')
def datenschutz():
    return render_template('datenschutz.html')

@app.route('/success')
def success():
    vorname = request.args.get('vorname', 'Gast')
    return render_template('success.html', vorname=vorname)

@app.route('/checkin/<unique_code>')
def checkin(unique_code):
    gast = Gast.query.filter_by(unique_code=unique_code).first_or_404()
    if not gast.anwesend:
        gast.anwesend = True
        gast.anwesenheit_geaendert_am = get_berlin_time()
        db.session.commit()
        status = 'eingecheckt'
    else:
        status = 'bereits_eingecheckt'
    timestamp = get_berlin_time().strftime('%d.%m.%Y um %H:%M')
    return render_template('checkin.html', gast=gast, status=status, timestamp=timestamp)

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("15 per hour")
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
            regenerate_session()
            flash('Erfolgreich angemeldet!', 'success')
            log_security_event('admin_login', success=True, user_id=username)
            return redirect(url_for('admin'))
        else:
            flash('Ungültige Anmeldedaten!', 'error')
            security_manager.record_failed_attempt(get_remote_address())
            log_security_event('admin_login_failed', success=False, user_id=username)
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Sie wurden abgemeldet.', 'info')
    return redirect(url_for('admin_login'))

@app.route('/admin')
@login_required
def admin():
    gaeste = Gast.query.order_by(Gast.registriert_am.desc()).all()
    return render_template('admin.html', gaeste=gaeste)

@app.route('/api/toggle_anwesenheit/<int:gast_id>', methods=['POST'])
@login_required
@limiter.limit("60 per hour")
def toggle_anwesenheit(gast_id):
    gast = Gast.query.get_or_404(gast_id)
    gast.anwesend = not gast.anwesend
    gast.anwesenheit_geaendert_am = get_berlin_time()
    db.session.commit()
    return jsonify({'success': True, 'anwesend': gast.anwesend})

@app.route('/api/bestatige_ticket/<int:gast_id>', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
def bestatige_ticket(gast_id):
    gast = Gast.query.get_or_404(gast_id)
    try:
        qr_code_base64 = generiere_qr_code(gast.unique_code)
        email_erfolg = sende_ticket_email(gast, qr_code_base64)
        if email_erfolg:
            gast.ticket_bestaetigt = True
            gast.ticket_bestaetigt_am = get_berlin_time()
            gast.ticket_versendet = True
            gast.ticket_versendet_am = get_berlin_time()
            db.session.commit()
            return jsonify({'success': True, 'message': 'Ticket wurde erfolgreich bestätigt und versendet!'})
        else:
            return jsonify({'success': False, 'message': 'Fehler beim Versenden der E-Mail'})
    except Exception as e:
        app.logger.error(f"Fehler beim Ticket-Versand: {str(e)}")
        return jsonify({'success': False, 'message': 'Ein Fehler ist aufgetreten'})

@app.route('/admin/gast/<int:gast_id>')
@login_required
def gast_details(gast_id):
    gast = Gast.query.get_or_404(gast_id)
    return render_template('gast_details.html', gast=gast)

@app.route('/admin/export-excel')
@login_required
@limiter.limit("10 per hour")
def export_excel():
    try:
        gaeste = Gast.query.order_by(Gast.registriert_am.desc()).all()
        excel_data = []
        for gast in gaeste:
            kinder_liste = gast.get_kinder_liste()
            kinder_text = ""
            if kinder_liste:
                kinder_namen = [f"{k.get('vorname','')} {k.get('nachname','')}" for k in kinder_liste]
                kinder_text = "; ".join(kinder_namen)
            registriert_am = ""
            if gast.get_formatted_registriert_am():
                registriert_am = gast.get_formatted_registriert_am().strftime('%d.%m.%Y %H:%M')
            elif gast.registriert_am:
                registriert_am = gast.registriert_am.strftime('%d.%m.%Y %H:%M')
            eingecheckt_am = ""
            if gast.get_formatted_anwesenheit_geaendert_am():
                eingecheckt_am = gast.get_formatted_anwesenheit_geaendert_am().strftime('%d.%m.%Y %H:%M')
            ticket_bestaetigt_am = ""
            if gast.ticket_bestaetigt_am:
                if gast.ticket_bestaetigt_am.tzinfo is None:
                    berlin_time = BERLIN_TZ.localize(gast.ticket_bestaetigt_am)
                else:
                    berlin_time = gast.ticket_bestaetigt_am.astimezone(BERLIN_TZ)
                ticket_bestaetigt_am = berlin_time.strftime('%d.%m.%Y %H:%M')
            excel_data.append({
                'ID': gast.id,
                'Vorname': gast.vorname,
                'Nachname': gast.nachname,
                'E-Mail': gast.email,
                'Telefon': gast.telefon,
                'Adresse': gast.adresse,
                'Hausnummer': gast.hausnr,
                'PLZ': gast.plz,
                'Ort': gast.ort,
                'Anzahl Kinder': gast.kinder,
                'Kinder Namen': kinder_text,
                'Eingeladen von': gast.berater,
                'Datenschutz Zustimmung': 'Ja' if gast.zustimmung else 'Nein',
                'Nachricht': gast.nachricht or '',
                'Status': 'Anwesend' if gast.anwesend else 'Abwesend',
                'Ticket bestätigt': 'Ja' if gast.ticket_bestaetigt else 'Nein',
                'Ticket versendet': 'Ja' if gast.ticket_versendet else 'Nein',
                'Registriert am': registriert_am,
                'Ticket bestätigt am': ticket_bestaetigt_am,
                'Eingecheckt am': eingecheckt_am,
                'QR-Code': gast.unique_code
            })
        df = pd.DataFrame(excel_data)
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Gästeliste', index=False)
            worksheet = writer.sheets['Gästeliste']
            column_widths = {'A': 8,'B': 15,'C': 15,'D': 25,'E': 15,'F': 20,'G': 12,'H': 8,'I': 15,'J': 12,'K': 30,'L': 30,'M': 18,'N': 30,'O': 12,'P': 15,'Q': 15,'R': 18,'S': 18,'T': 18,'U': 38}
            for col, width in column_widths.items():
                worksheet.column_dimensions[col].width = width
            from openpyxl.styles import Font, PatternFill, Alignment
            header_font = Font(bold=True, color='FFFFFF')
            header_fill = PatternFill(start_color='366092', end_color='366092', fill_type='solid')
            header_alignment = Alignment(horizontal='center', vertical='center')
            for cell in worksheet[1]:
                cell.font = header_font
                cell.fill = header_fill
                cell.alignment = header_alignment
        output.seek(0)
        today = datetime.now().strftime('%Y-%m-%d')
        filename = f'gaesteliste_{today}.xlsx'
        return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', as_attachment=True, download_name=filename)
    except Exception as e:
        app.logger.error(f"Fehler beim Excel-Export: {str(e)}")
        return jsonify({'error': 'Fehler beim Export'}), 500

@app.template_filter('berlin_time')
def berlin_time_filter(datetime_obj):
    if datetime_obj:
        if datetime_obj.tzinfo is None:
            berlin_time = BERLIN_TZ.localize(datetime_obj)
        else:
            berlin_time = datetime_obj.astimezone(BERLIN_TZ)
        return berlin_time.strftime('%d.%m.%Y um %H:%M')
    return '-'

@app.errorhandler(400)
def bad_request(e):
    return render_template('400.html'), 400

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('429.html'), 429

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    setup_logging()
    with app.app_context():
        db.create_all()
    app.run(host=os.environ.get('HOST', '0.0.0.0'), port=int(os.environ.get('PORT', '8000')), debug=False)
