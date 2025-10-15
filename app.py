from flask import Flask, render_template, jsonify
from scapy.all import rdpcap, Dot11, Dot11Elt
from collections import defaultdict
import os
import re
from datetime import datetime

app = Flask(__name__)

# Ruta del archivo .cap
CAP_FILE = "salida-01.cap"

# Ruta del archivo OUI (MAC vendors)
OUI_FILE = "oui.txt"

# Variable global para almacenar datos
data_cache = {
    'pkts': [],
    'last_loaded': None,
    'file_mtime': None
}

# Cache de MAC vendors
mac_vendors = {}

def load_oui_file():
    """Cargar archivo OUI con vendors de MAC addresses"""
    global mac_vendors

    if not os.path.exists(OUI_FILE):
        print(f"⚠️  Archivo {OUI_FILE} no encontrado")
        print("   Descárgalo con: wget http://standards-oui.ieee.org/oui/oui.txt -O oui.txt")
        return

    print(f"📖 Cargando MAC vendors desde {OUI_FILE}...")

    try:
        with open(OUI_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Formato: AA-BB-CC   (hex)		Vendor Name
                if '(hex)' in line:
                    parts = line.split('(hex)')
                    if len(parts) >= 2:
                        mac_prefix = parts[0].strip().replace('-', ':').lower()
                        vendor = parts[1].strip()
                        mac_vendors[mac_prefix] = vendor

        print(f"✅ Cargados {len(mac_vendors)} vendors")
    except Exception as e:
        print(f"❌ Error al cargar OUI: {e}")

def get_mac_vendor(mac_address):
    """Obtener vendor de una MAC address"""
    if not mac_address:
        return "Unknown"

    # Obtener los primeros 3 octetos (OUI)
    mac_clean = mac_address.lower().replace('-', ':')
    oui = ':'.join(mac_clean.split(':')[:3])

    return mac_vendors.get(oui, "Unknown")

def load_cap_file():
    """Cargar el archivo .cap y guardar en cache"""
    global data_cache
    try:
        if not os.path.exists(CAP_FILE):
            print(f"❌ Archivo no encontrado: {CAP_FILE}")
            return False

        current_mtime = os.path.getmtime(CAP_FILE)

        if data_cache['file_mtime'] == current_mtime and data_cache['pkts']:
            print("ℹ️  Archivo no ha cambiado, usando cache")
            return True

        print(f"🔄 Cargando archivo: {CAP_FILE}")
        pkts = rdpcap(CAP_FILE)

        data_cache['pkts'] = pkts
        data_cache['last_loaded'] = datetime.now()
        data_cache['file_mtime'] = current_mtime

        print(f"✅ Archivo cargado: {len(pkts)} paquetes")
        return True

    except Exception as e:
        print(f"❌ Error al cargar archivo: {e}")
        return False

def get_channel(pkt):
    """Extraer canal del paquete"""
    try:
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 3:  # DS Parameter Set
                    return int(elt.info[0]) if len(elt.info) > 0 else 0
                elt = elt.payload.getlayer(Dot11Elt)
        return 0
    except:
        return 0

def get_signal_strength(pkt):
    """Extraer fuerza de señal"""
    try:
        if hasattr(pkt, 'dBm_AntSignal'):
            return pkt.dBm_AntSignal
        return None
    except:
        return None

def process_wifi_packets():
    """Procesar paquetes WiFi"""
    access_points = {}
    stations = defaultdict(lambda: {'macs': [], 'count': 0})

    pkts = data_cache['pkts']

    for pkt in pkts:
        try:
            if pkt.haslayer(Dot11):
                # Procesar beacons (Access Points)
                if pkt.type == 0 and pkt.subtype == 8:  # Beacon
                    bssid = pkt.addr3
                    if bssid:
                        ssid = pkt.info.decode('utf-8', errors='ignore') if pkt.info else ""
                        channel = get_channel(pkt)
                        signal = get_signal_strength(pkt)

                        # Obtener encriptación
                        crypto = set()
                        if pkt.haslayer(Dot11Elt):
                            try:
                                elt = pkt[Dot11Elt]
                                while elt:
                                    if elt.ID == 48:  # RSN
                                        crypto.add("WPA2")
                                    elif elt.ID == 221 and len(elt.info) >= 4:
                                        if elt.info[:4] == b'\x00\x50\xf2\x01':
                                            crypto.add("WPA")
                                    elt = elt.payload.getlayer(Dot11Elt)
                            except:
                                pass

                        if pkt.FCfield & 0x40:
                            crypto.add("WEP")

                        encryption = "+".join(sorted(crypto)) if crypto else "Open"

                        if bssid in access_points:
                            if signal and (not access_points[bssid]['signal'] or signal > access_points[bssid]['signal']):
                                access_points[bssid]['signal'] = signal
                        else:
                            access_points[bssid] = {
                                'bssid': bssid,
                                'ssid': ssid if ssid else "(Hidden)",
                                'channel': channel,
                                'encryption': encryption,
                                'signal': signal
                            }

                # Procesar datos (Stations)
                elif pkt.type == 2:  # Data frame
                    station_mac = pkt.addr2
                    ap_mac = pkt.addr1
                    if station_mac and ap_mac:
                        if ap_mac in access_points:
                            if station_mac not in stations[ap_mac]['macs']:
                                stations[ap_mac]['macs'].append(station_mac)
                            stations[ap_mac]['count'] += 1
                        elif station_mac in access_points:
                            if ap_mac not in stations[station_mac]['macs']:
                                stations[station_mac]['macs'].append(ap_mac)
                            stations[station_mac]['count'] += 1

        except Exception as e:
            continue

    return access_points, dict(stations)

@app.route('/')
def home():
    """Página principal"""
    if not data_cache['pkts']:
        load_cap_file()
    return render_template('index.html')

@app.route('/api/data')
def get_data():
    """API endpoint para obtener datos"""
    load_cap_file()

    if not data_cache['pkts']:
        return jsonify({
            'error': 'No se pudo cargar el archivo .cap',
            'access_points': [],
            'total_packets': 0,
            'total_aps': 0,
            'last_update': None
        })

    access_points, stations = process_wifi_packets()

    # Preparar datos con vendors
    aps_list = []
    for bssid, ap_data in access_points.items():
        station_list = []
        for mac in stations.get(bssid, {}).get('macs', []):
            vendor = get_mac_vendor(mac)
            station_list.append({
                'mac': mac,
                'vendor': vendor
            })

        ap_data['clients'] = len(station_list)
        ap_data['stations'] = station_list
        aps_list.append(ap_data)

    # Ordenar por señal
    aps_list.sort(key=lambda x: (-(x['signal'] or -100), x['ssid']))

    return jsonify({
        'access_points': aps_list,
        'total_packets': len(data_cache['pkts']),
        'total_aps': len(access_points),
        'last_update': data_cache['last_loaded'].strftime('%Y-%m-%d %H:%M:%S') if data_cache['last_loaded'] else None,
        'file_path': CAP_FILE
    })

@app.route('/api/reload')
def reload_file():
    """Forzar recarga del archivo"""
    data_cache['file_mtime'] = None
    success = load_cap_file()

    return jsonify({
        'success': success,
        'packets': len(data_cache['pkts']) if success else 0,
        'last_update': data_cache['last_loaded'].strftime('%Y-%m-%d %H:%M:%S') if data_cache['last_loaded'] else None
    })

@app.route('/prueba')
def prueba():
    """Ruta de prueba"""
    if not data_cache['pkts']:
        load_cap_file()

    return f'''
    <h2>Estado del Sistema</h2>
    <ul>
        <li>Archivo CAP: {CAP_FILE} ({'✅ Existe' if os.path.exists(CAP_FILE) else '❌ No existe'})</li>
        <li>Archivo OUI: {OUI_FILE} ({'✅ Existe' if os.path.exists(OUI_FILE) else '❌ No existe'})</li>
        <li>Paquetes: {len(data_cache['pkts'])}</li>
        <li>Vendors cargados: {len(mac_vendors)}</li>
        <li>Última carga: {data_cache['last_loaded']}</li>
    </ul>
    <a href="/">Volver</a>
    '''

if __name__ == '__main__':
    # Cargar OUI al iniciar
    load_oui_file()
    # Cargar archivo al iniciar
    load_cap_file()
    app.run(debug=True, host='0.0.0.0', port=5000)