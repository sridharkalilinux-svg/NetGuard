import logging
from scapy.all import PcapReader, TCP, UDP, IP, Ether, Raw, DNS, ICMP, ARP
from datetime import datetime
from collections import defaultdict
import socket

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_protocol_name(proto_num):
    # Common protocols
    proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return proto_map.get(proto_num, str(proto_num))

def is_private_ip(ip):
    # Check for private IP ranges (RFC 1918)
    # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    try:
        parts = list(map(int, ip.split('.')))
        if parts[0] == 10: return True
        if parts[0] == 172 and 16 <= parts[1] <= 31: return True
        if parts[0] == 192 and parts[1] == 168: return True
        if ip == '127.0.0.1': return True
    except:
        pass
    return False

def analyze_pcap(file_path):
    """
    Analyzes a PCAP file and returns a structured summary.
    """
    sessions = defaultdict(lambda: {
        'start_time': None,
        'end_time': None,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'protocol': None,
        'packet_count': 0,
        'bytes_sent': 0,
        'payloads': [],
        'flags': set()
    })
    
    general_stats = {
        'total_packets': 0,
        'protocols': defaultdict(int),
        'start_time': None,
        'end_time': None,
        'ips': set()
    }

    try:
        with PcapReader(file_path) as pcap_reader:
            for pkt in pcap_reader:
                general_stats['total_packets'] += 1
                
                # Timestamp
                ts = float(pkt.time)
                if general_stats['start_time'] is None or ts < general_stats['start_time']:
                    general_stats['start_time'] = ts
                if general_stats['end_time'] is None or ts > general_stats['end_time']:
                    general_stats['end_time'] = ts

                if not pkt.haslayer(IP):
                    continue

                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto = get_protocol_name(ip_layer.proto)
                
                general_stats['protocols'][proto] += 1
                general_stats['ips'].add(src_ip)
                general_stats['ips'].add(dst_ip)

                src_port = 0
                dst_port = 0
                payload_data = b""
                tcp_flags = None

                if pkt.haslayer(TCP):
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                    payload_data = bytes(pkt[TCP].payload)
                    tcp_flags = pkt[TCP].flags
                elif pkt.haslayer(UDP):
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
                    payload_data = bytes(pkt[UDP].payload)
                elif pkt.haslayer(ICMP):
                    # ICMP doesn't have ports, use 0
                    payload_data = bytes(pkt[ICMP].payload)

                # Identify session key (canonical flow)
                # We sort IP/Port pairs to group bi-directional traffic into one session
                # Or we can keep them separate. The prompt implies "Sessions/flows", usually 5-tuple.
                # Let's keep distinct flows for now to detect "Inbound vs Outbound" easier, 
                # but "Session" usually implies the conversation. 
                # Let's use a tuple that groups them: tuple(sorted((src, dst)) + sorted((sport, dport)) + (proto,))
                # But to track "Inbound vs Outbound", we need to know who started it. 
                # Let's stick to unidirectional flows for analysis (easier for detecting "high SYN from IP")
                # and then group them for display if needed.
                # Actually, standard flow analysis is unidirectional.
                
                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                
                session = sessions[flow_key]
                if session['src_ip'] is None:
                    session['src_ip'] = src_ip
                    session['dst_ip'] = dst_ip
                    session['src_port'] = src_port
                    session['dst_port'] = dst_port
                    session['protocol'] = proto
                    session['start_time'] = ts
                
                session['end_time'] = ts
                session['packet_count'] += 1
                session['bytes_sent'] += len(pkt)
                
                if tcp_flags:
                    session['flags'].add(str(tcp_flags))
                
                # Store interesting payloads (e.g. HTTP, DNS queries, etc.)
                # Limiting payload storage to avoid memory explosion
                if len(payload_data) > 0 and len(session['payloads']) < 20: 
                    # Decode if possible, else store repr
                    try:
                        decoded = payload_data.decode('utf-8', errors='ignore')
                        # Simple heuristic to keep only "text-like" data
                        if any(c in decoded for c in ('GET', 'POST', 'HTTP', 'ssh', 'SELECT', 'UNION', 'User-Agent', 'USER', 'PASS', 'Authorization')):
                            session['payloads'].append(decoded)
                        elif proto == 'DNS':
                             session['payloads'].append(repr(payload_data))
                    except:
                        pass

    except Exception as e:
        logger.error(f"Error parsing PCAP: {e}")
        return None

    # Post-process sessions
    processed_sessions = []
    for k, v in sessions.items():
        duration = v['end_time'] - v['start_time']
        v['duration'] = duration
        v['flags'] = list(v['flags']) # Convert set to list for JSON serialization
        processed_sessions.append(v)
        
    general_stats['ips'] = list(general_stats['ips']) # Convert set to list

    return {
        'stats': general_stats,
        'sessions': processed_sessions
    }
