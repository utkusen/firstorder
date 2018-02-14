import argparse
import operator
import threading
import requests
from requests import ConnectionError
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy_http import http
from time import sleep

banner = """
                .==.     A traffic analyzer to evade Empire's communication            
               ()''()-.       __ _          _                _      
    .---.       ;--; /       / _(_)        | |              | | 
  .'_:___'. _..'.  __'.     | |_ _ _ __ ___| |_ ___  _ __ __| | ___ _ __ 
  |__ --==|'-''' /'...;     |  _| | '__/ __| __/ _ \| '__/ _` |/ _ \ '__|  
  [  ]  :[|       |---/     | | | | |  \__ \ || (_) | | | (_| |  __/ |    
  |__|  =[|     .'    '.    |_| |_|_|  |___/\__\___/|_|  \__,_|\___|_|
  / / ____|     :       '._           
 |-/.____.'      | :       :        by Utku Sen, Gozde Sinturk
/___\ /___\      '-'._----'              TEAR Security 
"""

progress_current = 0
progress_last_updated = 0
progress_update_timeout = 1
scan_result = {
    "arp_broadcasts": {},
    "ldap_users": {},
    "ports": {"src": {}, "dst": {}},
    "protocols": {"list": set(), "proto": {}, "total": 0},
    "server": {},
    "request": {"path": {}, "user-agent": {}}
}
scan_settings_verbose = False
watchdog_last_packet_parsed_at = 0
watchdog_stop_flag = False
headers = {'Content-Type': 'application/json'}
requests.packages.urllib3.disable_warnings()

def add_to_scan_result(data, result):

    if type(data) is list:
        # Add protocols stack
        s = result
        s["total"] += 1
        proto_prev_name = None
        for proto_name in data:
            if proto_name is "Padding":
                continue
            if proto_name == proto_prev_name:
                continue
            if proto_name not in s["proto"]:
                s["proto"][proto_name] = {"proto": {}, "total": 0}
            s = s["proto"][proto_name]
            s["total"] += 1
            result["list"].update({proto_name})
            proto_prev_name = proto_name
    else:
        # Add a single value
        if data in result:
            result[data] += 1
        else:
            result[data] = 1


def error(message):
    """Outputs error message to STDERR."""

    sys.stderr.write("{prog}: error: {msg}".format(prog=os.path.basename(sys.argv[0]), msg=message+os.linesep))


def parse_raw(load, word):
    result = []
    lines = load.split("\r\n")
    for line in lines:
        if word in line:
            result.append(line.split(":")[1])
    return result

def parse_packet(pkt):

    global scan_result
    global watchdog_last_packet_parsed_at

    if scan_settings_verbose:
        progress_update(1)

    if pkt.haslayer("ARP"):
        if pkt.dst == 'ff:ff:ff:ff:ff:ff':
            add_to_scan_result(pkt.psrc, scan_result["arp_broadcasts"])

    if pkt.haslayer("TCP") or pkt.haslayer("UDP"):
        if pkt.dport == 389 or pkt.sport == 389 or pkt.dport == 636 or pkt.sport == 636:
            add_to_scan_result(pkt["IP"].dst, scan_result["ldap_users"])
            add_to_scan_result(pkt["IP"].src, scan_result["ldap_users"])

    if hasattr(pkt, "dport"):
        add_to_scan_result(pkt.dport, scan_result["ports"]["dst"])
    if hasattr(pkt, "sport"):
        add_to_scan_result(pkt.sport, scan_result["ports"]["src"])

    if pkt.haslayer(http.HTTPResponse):
        if hasattr(pkt, "Server"):
            add_to_scan_result(pkt.Server, scan_result["server"])

    if pkt.haslayer(http.HTTPRequest):
        if hasattr(pkt, "User-Agent"):
            add_to_scan_result(getattr(pkt, "User-Agent"), scan_result["request"]["user-agent"])

    if pkt.haslayer(http.HTTPRequest):
        if hasattr(pkt, "Path"):
            add_to_scan_result(getattr(pkt, "Path"), scan_result["request"]["path"])

    if pkt.haslayer("UDP") and pkt["UDP"].dport == 1900:
        for ua in parse_raw(pkt["Raw"].load, "USER-AGENT"):
            add_to_scan_result(ua, scan_result["request"]["user-agent"])
        for srv in parse_raw(pkt["Raw"].load, "Server"):
            add_to_scan_result(srv, scan_result["server"])

    watchdog_last_packet_parsed_at = time.time()


def port_stats(data, port_type):
    if port_type != "src" and port_type != "dst":
        print "port_type must be 'src' or 'dst'"
        return None
    print "=== Top 10 Port Statistics ==="
    print
    if len(port_type) <= 0:
        return None

    records = sorted(data[port_type].items(), key=operator.itemgetter(1), reverse=True)
    total = sum(data[port_type].values())
    for record in records[:10]:
        templ = "Port {port}: {num}/{ttl} ({shr:.2f}%)"
        share = float(record[1]) / total * 100
        print templ.format(port=record[0], num=record[1], ttl=total, shr=share)
    print
    return records[0][0]


def server_stats(data):
    print "=== Top 10 Server Headers ==="
    print
    if len(data) <= 0:
        return None

    records = sorted(data.items(), key=operator.itemgetter(1), reverse=True)
    total = sum(data.values())
    for record in records[:10]:
        templ = "Server: {name}: {num}/{ttl} ({shr:.2f}%)"
        share = float(record[1]) / total * 100
        print templ.format(name=record[0], num=record[1], ttl=total, shr=share)
    print
    return records[0][0]


def useragent_stats(data):
    print "=== Top 10 User-Agent Headers ==="
    print
    if len(data) <= 0:
        return None

    records = sorted(data.items(), key=operator.itemgetter(1), reverse=True)
    total = sum(data.values())
    for record in records[:10]:
        templ = "User-Agent: {name}: {num}/{ttl} ({shr:.2f}%)"
        share = float(record[1]) / total * 100
        print templ.format(name=record[0], num=record[1], ttl=total, shr=share)
    print
    return records[0][0]


def uri_stats(data):
    print "=== Top 10 GET Request URI ==="
    print
    if len(data) <= 0:
        return None

    records = sorted(data.items(), key=operator.itemgetter(1), reverse=True)
    total = sum(data.values())
    for record in records[:10]:
        templ = "GET request URI: {name}: {num}/{ttl} ({shr:.2f}%)"
        share = float(record[1]) / total * 100
        print templ.format(name=record[0], num=record[1], ttl=total, shr=share)
    print
    uri_list = []
    uri_list.append(records[0][0].split('?')[0])
    uri_list.append(records[1][0].split('?')[0])
    uri_list.append(records[2][0].split('?')[0])
    return uri_list


def arp_stats(data):
    print "=== Number of Unique IP addresses (ARP)==="
    print
    if len(data) <= 0:
        return 0

    records = sorted(data.items(), key=operator.itemgetter(1), reverse=True)
    print len(records)
    return len(records)


def ldap_stats(data):
    print "=== Number of Unique Computer Names (LDAP)==="
    print
    if len(data) <= 0:
        return 0

    records = sorted(data.items(), key=operator.itemgetter(1), reverse=True)
    print len(records)
    return len(records)


def progress_reset():

    global progress_current
    global progress_last_updated

    progress_current = 0
    progress_last_updated = 0


def progress_update(increment=0, force_print=False):

    global progress_current
    global progress_last_updated
    global progress_update_timeout

    progress_current += increment
    if force_print or time.time() > (progress_last_updated + progress_update_timeout):
        print "{} packets scanned...".format(progress_current)
        progress_last_updated = time.time()


def scan_files(files):
    """Initiates pcap files scan for statistics."""

    for f in files:
        if scan_settings_verbose:
            progress_reset()
            print "Scanning '{}'...".format(f)
            progress_update()
        start_watchdog(True)
        sniff(offline=f, store=0, prn=parse_packet)
        stop_watchdog()
        if scan_settings_verbose:
            progress_update(force_print=True)
            print "Scanning '{}' complete!".format(f)
    if scan_settings_verbose:
        print


def start_watchdog(init=False):

    global watchdog_last_packet_parsed_at
    global watchdog_stop_flag

    if init:
        watchdog_last_packet_parsed_at = time.time()
        watchdog_stop_flag = False
    if not watchdog_stop_flag:
        if watchdog_last_packet_parsed_at + 3 < time.time():
            thread.interrupt_main()
        else:
            threading.Timer(3, start_watchdog).start()


def stop_watchdog():

    global watchdog_stop_flag
    watchdog_stop_flag = True

def login(username,password):
    creds = {'username': username,'password': password}
    try:
        r = requests.post('https://127.0.0.1:1337/api/admin/login', json=creds, headers=headers, verify=False)

        if r.status_code == 200:
            token = r.json()['token']
            return token
        else:
            print "Login failed"
    except ConnectionError:
        print 'Connection Error'    

def start_http_listener(options,token):    
    r = requests.post('https://127.0.0.1:1337/api/listeners/http?token='+token, headers=headers, json=options, verify=False)
    if r.status_code == 200:
        print "Listener created"
    else:
        print "Error occured on listener creation"

def action(filename,empuser,emppass):
    scan_files(filename)
    global scan_result
    port = port_stats(scan_result["ports"], "dst")
    server = server_stats(scan_result["server"])
    agent = useragent_stats(scan_result["request"]["user-agent"])
    path = uri_stats(scan_result["request"]["path"])
    arp = arp_stats(scan_result["arp_broadcasts"])
    ldap = ldap_stats(scan_result["ldap_users"])
    if empuser is None or emppass is None:
        pass
    else:
        token = login(empuser,emppass)
        try:
            default_profile = path[0] + "," + path[1] + "," + path[2] + "|" + agent
        except:
            default_profile = None        
        if arp > ldap:
            number_of_computers = arp
        else:
            number_of_computers = ldap

        if int(number_of_computers) < 25:
            default_delay = 25
        elif int(number_of_computers) > 25 and int(number_of_computers) < 50:
            default_delay = 20
        elif int(number_of_computers) > 50 and int(number_of_computers) < 75:
            default_delay = 15
        elif int(number_of_computers) > 75 and int(number_of_computers) < 100:
            default_delay = 10
        elif int(number_of_computers) > 100:
            default_delay = 5

           
        if default_profile is not None:
            options = {'Name':'firstorder','Port':port,'ServerVersion':server,'DefaultProfile':default_profile,'DefaultDelay':default_delay}
        else:
            options = {'Name':'firstorder','Port':port,'ServerVersion':server,'DefaultDelay':default_delay}

        start_http_listener(options,token)    
                  


parser = argparse.ArgumentParser()
parser.add_argument('-f', nargs='+', action='store', dest='filename', help='Location of the pcap file', required=True)
parser.add_argument('-u', action='store', dest='empuser', help='Username of the Empire REST API', required=False)
parser.add_argument('-p', action='store', dest='emppass', help='Password of the Empire REST API', required=False)
argv = parser.parse_args()
scan_settings_verbose = True
print banner
action(argv.filename,argv.empuser,argv.emppass)





