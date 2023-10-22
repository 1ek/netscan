import os
import re
import sys
import subprocess
from dotenv import load_dotenv
from flask import Flask, jsonify
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import create_engine, String, select
from sqlalchemy.orm import Session, DeclarativeBase, Mapped, mapped_column
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_HOST = os.getenv('DB_HOST')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')

NETWORK_VNC_PORT=os.getenv('NETWORK_VNC_PORT')
NETWORK_SUBNET=os.getenv('NETWORK_SUBNET')

DATABASE_URI = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
engine = create_engine(DATABASE_URI, echo=True)

class Base(DeclarativeBase):
    pass

class Device(Base):
    __tablename__ = 'device'
    id: Mapped[int] = mapped_column(primary_key=True)
    host: Mapped[str] = mapped_column(String)

def query_ips():
    try:
        session = Session(bind=engine)
        ips = session.scalars(select(Device.host)).all()
        session.close()
        return ips
    except SQLAlchemyError as e:
        return f'ERROR: {e}'

def send_command(command):
    return subprocess.check_output(command, shell=True).decode()

def log(output):
    print(output, file=sys.stderr)

    
@app.route('/pingall', methods=['GET'])
def pingAll():
    ips = query_ips()
    ips_string = ' '.join(ips)
    log(f'FETCHED IPS: {ips}')
    output = send_command(f'nmap -T4 -sP {ips_string}')
    log(output)
    hosts = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
    result = {
        'hosts': hosts,
    }

    return jsonify(result)

@app.route('/ping/<ip>', methods=['GET'])
def pingIP(ip):
    output = send_command(f'nmap -T4 -sP {ip}')
    log(output)
    result = { 'online': True if re.search(r'1 host up', output) else False }

    return jsonify(result)

@app.route('/scan', methods=['GET'])
def scanForOpenVNC():
    output = send_command(f'nmap -T4 -p {NETWORK_VNC_PORT} --open {NETWORK_SUBNET}')
    log(output)
    hosts = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
    known_hosts = query_ips()
    unknown_hosts = [i for i in hosts if i not in known_hosts]
    scan_duration_match = re.search(r'scanned in (\d+\.\d+)', output)
    scan_duration = scan_duration_match.group(1)
    result = {
        'hosts': hosts,
        'unknown_hosts': unknown_hosts,
        'duration': scan_duration
    }

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')