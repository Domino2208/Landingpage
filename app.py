from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from PIL import Image
import qrcode
import io
import base64
import uuid
from datetime import datetime
import os
import json
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import pandas as pd
from io import BytesIO

app = Flask(__name__)

# Konfiguration
app.config['SECRET_KEY'] = 'admin123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gaeste.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# E-Mail Konfiguration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sts.formulare@gmail.com'
app.config['MAIL_PASSWORD'] = 'aeya mvwl rgar qtob'

# Admin Konfiguration
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD_HASH = generate_password_hash('admin123')  # Ändern Sie das Passwort!

# Berlin Zeitzone
BERLIN_TZ = pytz.timezone('Europe/Berlin')

db = SQLAlchemy(app)
mail = Mail(app)

def get_berlin_time():
    """Gibt die aktuelle Zeit in Berlin Zeitzone zurück"""
    return datetime.now(BERLIN_TZ)

def login_required(f):
    """Decorator für Admin-Login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Datenbank Modell
class Gast(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vorname = db.Column(db.String(100), nullable=False)
    nachname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    adresse = db.Column(db.String(200), nullable=False)
    hausnr = db.Column(db.String, nullable=False)
    plz = db.Column(db.String, nullable=False)
    ort = db.Column(db.String(100), nullable=False)
    telefon = db.Column(db.String(20), nullable=False)
    kinder = db.Column(db.String(20), nullable=False)
    kinder_daten = db.Column(db.Text, nullable=True)
    zustimmung = db.Column(db.String, nullable=False)
    nachricht = db.Column(db.Text, nullable=True)
    unique_code = db.Column(db.String(36), unique=True, nullable=False)
    anwesend = db.Column(db.Boolean, default=False)
    registriert_am = db.Column(db.DateTime, default=get_berlin_time)
    anwesenheit_geaendert_am = db.Column(db.DateTime, nullable=True)

    def get_kinder_liste(self):
        """Gibt die Kinderdaten als Python-Liste zurück"""
        if self.kinder_daten:
            try:
                return json.loads(self.kinder_daten)
            except json.JSONDecodeError:
                return []
        return []

    def set_kinder_liste(self, kinder_liste):
        """Speichert die Kinderdaten als JSON String"""
        self.kinder_daten = json.dumps(kinder_liste, ensure_ascii=False)

    def get_formatted_registriert_am(self):
        """Gibt das Registrierungsdatum in Berlin-Zeit formatiert zurück"""
        if self.registriert_am:
            if self.registriert_am.tzinfo is None:
                berlin_time = BERLIN_TZ.localize(self.registriert_am)
            else:
                berlin_time = self.registriert_am.astimezone(BERLIN_TZ)
            return berlin_time
        return None

    def get_formatted_anwesenheit_geaendert_am(self):
        """Gibt das Check-in Datum in Berlin-Zeit formatiert zurück"""
        if self.anwesenheit_geaendert_am:
            if self.anwesenheit_geaendert_am.tzinfo is None:
                berlin_time = BERLIN_TZ.localize(self.anwesenheit_geaendert_am)
            else:
                berlin_time = self.anwesenheit_geaendert_am.astimezone(BERLIN_TZ)
            return berlin_time
        return None

    def __repr__(self):
        return f'<Gast {self.vorname} {self.nachname}>'

# QR-Code Generator
def generiere_qr_code(unique_code):
    qr_url = f"{request.url_root}checkin/{unique_code}"
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_url)
    qr.make(fit=True)

    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")

    # Hintergrund und Logo aus static laden
    hintergrund_path = os.path.join(app.root_path, "static", "bilder", "ticket_hintergrund.jpg")
    logo_path = os.path.join(app.root_path, "static", "bilder", "sts-logo.png")

    hintergrund = Image.open(hintergrund_path).convert("RGBA")
    logo = Image.open(logo_path).convert("RGBA")

    # Logo skalieren
    logo_width = int(hintergrund.width * 0.65)
    logo_height = int(logo.height * (logo_width / logo.width))
    logo = logo.resize((logo_width, logo_height), Image.LANCZOS)

    # QR-Code skalieren
    qr_size = int(hintergrund.width * 0.55)
    qr_img = qr_img.resize((qr_size, qr_size), Image.LANCZOS)

    # Logo auf Hintergrund
    logo_x = (hintergrund.width - logo.width) // 2
    logo_y = int(hintergrund.height * 0.05)
    hintergrund.paste(logo, (logo_x, logo_y), logo)

    # QR-Code auf Hintergrund
    qr_x = (hintergrund.width - qr_img.width) // 2
    qr_y = (hintergrund.height - qr_img.height) // 2
    hintergrund.paste(qr_img, (qr_x, qr_y), qr_img)

    # Bild als Bytes zurückgeben
    img_buffer = io.BytesIO()
    hintergrund.save(img_buffer, format="PNG")
    img_buffer.seek(0)

    return base64.b64encode(img_buffer.getvalue()).decode()

# E-Mail senden
def sende_bestaetigung_email(gast, qr_code_base64):
    try:
        qr_bytes = base64.b64decode(qr_code_base64)

        kinder_liste = gast.get_kinder_liste()
        kinder_text = ""
        if kinder_liste:
            kinder_text = "<h3>Angemeldete Kinder:</h3><ul>"
            for i, kind in enumerate(kinder_liste, 1):
                kinder_text += f"<li>Kind {i}: {kind['vorname']} {kind['nachname']}</li>"
            kinder_text += "</ul>"

        msg = Message(
            subject='Ihre Anmeldung wurde bestätigt - QR-Code anbei',
            sender=app.config['MAIL_USERNAME'],
            recipients=[gast.email]
        )
        
        msg.html = f"""
        <html>
        <body>
            <h2>Hallo {gast.vorname}!</h2>
            <p>Ihre Anmeldung wurde erfolgreich bestätigt.</p>
            
            <h3>Ihre Anmeldedaten:</h3>
            <p><strong>Name:</strong> {gast.vorname} {gast.nachname}</p>
            <p><strong>E-Mail:</strong> {gast.email}</p>
            <p><strong>Telefon:</strong> {gast.telefon}</p>
            <p><strong>Anzahl Kinder:</strong> {gast.kinder}</p>
            
            {kinder_text}
            
            <p>Bitte verwenden Sie den untenstehenden QR-Code für Ihren Check-in:</p>
            <img src="data:image/png;base64,{qr_code_base64}" alt="QR Code">
            <p><b>Anhang:</b> Der QR-Code befindet sich zusätzlich als Datei im Anhang dieser E-Mail.</p>
            <br>
            <p>Vielen Dank für Ihre Anmeldung!</p>
            <p><strong>Ihr Team von STS Schumacher Finanzen & Consulting</strong></p>
        </body>
        </html>
        """

        msg.attach("qr-code.png", "image/png", qr_bytes)
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Fehler beim E-Mail-Versand: {str(e)}")
        return False

# Routen
@app.route('/')
def index():
    return render_template('landingpage.html')

@app.route('/register', methods=['POST'])
def register():
    vorname = request.form.get('vorname')
    nachname = request.form.get('nachname')
    email = request.form.get('email')
    telefon = request.form.get('telefon', '')
    adresse = request.form.get('adresse', '')
    hausnr = request.form.get('hausnr', '')
    plz = request.form.get('plz', '')
    ort = request.form.get('ort', '')
    kinder = request.form.get('kinder', '0')
    zustimmung = request.form.get('zustimmung') 
    nachricht = request.form.get('nachricht', '')

    if not kinder:
        kinder = '0'
    
    # Kinder-Daten sammeln
    kinder_liste = []
    anzahl_kinder = int(kinder) if kinder.isdigit() else 0
    
    for i in range(1, anzahl_kinder + 1):
        kind_vorname = request.form.get(f'kind{i}_vorname')
        kind_nachname = request.form.get(f'kind{i}_nachname')
        
        if not kind_vorname or not kind_nachname:
            return redirect(url_for('index', error=f'Bitte geben Sie Vor- und Nachname für Kind {i} an.'))
        
        kinder_liste.append({
            'vorname': kind_vorname.strip(),
            'nachname': kind_nachname.strip()
        })
    
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
        kinder=kinder,
        zustimmung=zustimmung,
        nachricht=nachricht,
        unique_code=unique_code,
        registriert_am=get_berlin_time()
    )
    
    neuer_gast.set_kinder_liste(kinder_liste)
    
    try:
        db.session.add(neuer_gast)
        db.session.commit()
        
        qr_code_base64 = generiere_qr_code(unique_code)
        email_erfolg = sende_bestaetigung_email(neuer_gast, qr_code_base64)
        
        if email_erfolg:
            return redirect(url_for('success', vorname=vorname, nachname=nachname, unique_code=unique_code))
        else:
            return redirect(url_for('index', error='Registrierung erfolgreich, aber E-Mail konnte nicht gesendet werden'))
            
    except Exception as e:
        db.session.rollback()
        print(f"Fehler bei der Registrierung: {str(e)}")
        return redirect(url_for('index', error='Ein Fehler ist aufgetreten'))

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
    
    # Berlin Zeitstempel für Template
    timestamp = get_berlin_time().strftime('%d.%m.%Y um %H:%M')
    
    return render_template('checkin.html', gast=gast, status=status, timestamp=timestamp)

# Admin Login Routen
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
            flash('Erfolgreich angemeldet!', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Ungültige Anmeldedaten!', 'error')
    
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

@app.route('/api/toggle_anwesenheit/<int:gast_id>')
@login_required
def toggle_anwesenheit(gast_id):
    gast = Gast.query.get_or_404(gast_id)
    gast.anwesend = not gast.anwesend
    gast.anwesenheit_geaendert_am = get_berlin_time()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'anwesend': gast.anwesend
    })

@app.route('/admin/gast/<int:gast_id>')
@login_required
def gast_details(gast_id):
    gast = Gast.query.get_or_404(gast_id)
    return render_template('gast_details.html', gast=gast)

# Excel Export Route
@app.route('/admin/export-excel')
@login_required
def export_excel():
    try:
        # Alle Gäste aus der Datenbank holen
        gaeste = Gast.query.order_by(Gast.registriert_am.desc()).all()
        
        # Daten für Excel vorbereiten
        excel_data = []
        for gast in gaeste:
            # Kinder-Daten aufbereiten
            kinder_liste = gast.get_kinder_liste()
            kinder_text = ""
            if kinder_liste:
                kinder_namen = [f"{kind['vorname']} {kind['nachname']}" for kind in kinder_liste]
                kinder_text = "; ".join(kinder_namen)
            
            # Zeitstempel formatieren
            registriert_am = ""
            if gast.get_formatted_registriert_am():
                registriert_am = gast.get_formatted_registriert_am().strftime('%d.%m.%Y %H:%M')
            elif gast.registriert_am:
                registriert_am = gast.registriert_am.strftime('%d.%m.%Y %H:%M')
                
            eingecheckt_am = ""
            if gast.get_formatted_anwesenheit_geaendert_am():
                eingecheckt_am = gast.get_formatted_anwesenheit_geaendert_am().strftime('%d.%m.%Y %H:%M')
            
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
                'Datenschutz Zustimmung': 'Ja' if gast.zustimmung else 'Nein',
                'Nachricht': gast.nachricht or '',
                'Status': 'Anwesend' if gast.anwesend else 'Abwesend',
                'Registriert am': registriert_am,
                'Eingecheckt am': eingecheckt_am,
                'QR-Code': gast.unique_code
            })
        
        # DataFrame erstellen
        df = pd.DataFrame(excel_data)
        
        # Excel-Datei in Memory erstellen
        output = BytesIO()
        
        # Excel Writer mit Styling
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Gästeliste', index=False)
            
            # Worksheet holen für Styling
            worksheet = writer.sheets['Gästeliste']
            
            # Spaltenbreite anpassen
            column_widths = {
                'A': 8,   # ID
                'B': 15,  # Vorname
                'C': 15,  # Nachname
                'D': 25,  # E-Mail
                'E': 15,  # Telefon
                'F': 20,  # Adresse
                'G': 12,  # Hausnummer
                'H': 8,   # PLZ
                'I': 15,  # Ort
                'J': 12,  # Anzahl Kinder
                'K': 30,  # Kinder Namen
                'L': 18,  # Datenschutz
                'M': 30,  # Nachricht
                'N': 12,  # Status
                'O': 18,  # Registriert am
                'P': 18,  # Eingecheckt am
                'Q': 38   # QR-Code
            }
            
            for col, width in column_widths.items():
                worksheet.column_dimensions[col].width = width
            
            # Header-Stil
            from openpyxl.styles import Font, PatternFill, Alignment
            
            header_font = Font(bold=True, color='FFFFFF')
            header_fill = PatternFill(start_color='366092', end_color='366092', fill_type='solid')
            header_alignment = Alignment(horizontal='center', vertical='center')
            
            # Header-Styling anwenden
            for cell in worksheet[1]:
                cell.font = header_font
                cell.fill = header_fill
                cell.alignment = header_alignment
        
        output.seek(0)
        
        # Aktuelles Datum für Dateiname
        today = datetime.now().strftime('%Y-%m-%d')
        filename = f'gaesteliste_{today}.xlsx'
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        print(f"Fehler beim Excel-Export: {str(e)}")
        return jsonify({'error': 'Fehler beim Export'}), 500

# Template Filter für Berlin Zeit
@app.template_filter('berlin_time')
def berlin_time_filter(datetime_obj):
    if datetime_obj:
        if datetime_obj.tzinfo is None:
            berlin_time = BERLIN_TZ.localize(datetime_obj)
        else:
            berlin_time = datetime_obj.astimezone(BERLIN_TZ)
        return berlin_time.strftime('%d.%m.%Y um %H:%M')
    return '-'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(debug=True, host='192.168.3.184', port=5000)