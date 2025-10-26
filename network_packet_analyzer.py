import socket
import struct
import textwrap
import time
from datetime import datetime
import os
import sys

class NetworkPacketAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.start_time = None
        
    def main_menu(self):
        """Display main menu"""
        print("\n" + "="*60)
        print("🔍 NETWORK PACKET ANALYZER - EDUCATIONAL TOOL")
        print("="*60)
        print("⚠️  WARNING: Use only on networks you own or have permission to monitor!")
        print("="*60)
        print("1. Start Packet Capture")
        print("2. View Capture Statistics")
        print("3. Clear Screen")
        print("4. Exit")
        print("="*60)
        
    def get_interface(self):
        """Get network interface to sniff on"""
        print("\n🌐 Available Interfaces:")
        print("1. All Interfaces (Default)")
        print("2. Specific Interface")
        
        choice = input("Choose (1/2): ").strip()
        if choice == "2":
            interface = input("Enter interface name (e.g., eth0, wlan0): ").strip()
            return interface
        return None
    
    def create_socket(self, interface=None):
        """Create raw socket for packet capture"""
        try:
            # Create raw socket
            if os.name == 'nt':  # Windows
                sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sniffer.bind(('0.0.0.0', 0))
                sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:  # Unix/Linux
                sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            return sniffer
        except PermissionError:
            print("❌ ERROR: Administrator/root privileges required!")
            print("💡 On Linux/Mac: Run with 'sudo'")
            print("💡 On Windows: Run as Administrator")
            return None
        except Exception as e:
            print(f"❌ Socket creation failed: {e}")
            return None
    
    def ethernet_frame(self, data):
        """Parse Ethernet frame"""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]
    
    def get_mac_addr(self, bytes_addr):
        """Convert MAC address to readable format"""
        return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
    
    def ipv4_packet(self, data):
        """Parse IPv4 packet"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]
    
    def ipv4(self, addr):
        """Convert IPv4 address to readable format"""
        return '.'.join(map(str, addr))
    
    def icmp_packet(self, data):
        """Parse ICMP packet"""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]
    
    def tcp_segment(self, data):
        """Parse TCP segment"""
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = offset_reserved_flags & 0x1FF
        
        return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]
    
    def udp_segment(self, data):
        """Parse UDP segment"""
        src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, length, data[8:]
    
    def format_multi_line(self, prefix, string, size=80):
        """Format multi-line data"""
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    
    def protocol_name(self, proto_num):
        """Convert protocol number to name"""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP',
            41: 'IPv6',
            89: 'OSPF'
        }
        return protocols.get(proto_num, f'Unknown({proto_num})')
    
    def tcp_flags(self, flags):
        """Parse TCP flags"""
        flag_names = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR', 'NS']
        active_flags = []
        for i, name in enumerate(flag_names):
            if flags & (1 << i):
                active_flags.append(name)
        return '|'.join(active_flags) if active_flags else 'None'
    
    def display_packet_info(self, timestamp, protocol, src_ip, dest_ip, src_port, dest_port, flags=None, payload=None):
        """Display formatted packet information"""
        print(f"\n📦 Packet #{self.packet_count}")
        print(f"🕒 Time: {timestamp}")
        print(f"📡 Protocol: {protocol}")
        print(f"📤 Source: {src_ip}:{src_port}" if src_port else f"📤 Source: {src_ip}")
        print(f"📥 Destination: {dest_ip}:{dest_port}" if dest_port else f"📥 Destination: {dest_ip}")
        
        if flags:
            print(f"🚩 TCP Flags: {flags}")
        
        if payload and len(payload) > 0:
            print(f"📊 Payload Size: {len(payload)} bytes")
            if len(payload) <= 100:  # Only show small payloads
                print("📝 Payload (hex):")
                print(self.format_multi_line('   ', payload))
        
        print("-" * 60)
    
    def start_capture(self, packet_count=50, timeout=30):
        """Start packet capture"""
        print(f"\n🎯 Starting packet capture...")
        print(f"📦 Packets to capture: {packet_count}")
        print(f"⏱️  Timeout: {timeout} seconds")
        print("⏹️  Press Ctrl+C to stop early")
        print("-" * 60)
        
        sniffer = self.create_socket()
        if not sniffer:
            return
        
        self.packet_count = 0
        self.start_time = time.time()
        
        try:
            sniffer.settimeout(1)  # 1 second timeout for non-blocking
            
            while self.packet_count < packet_count and (time.time() - self.start_time) < timeout:
                try:
                    raw_data, addr = sniffer.recvfrom(65535)
                    self.packet_count += 1
                    self.process_packet(raw_data)
                    
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    print("\n⏹️  Capture stopped by user")
                    break
                    
        except Exception as e:
            print(f"❌ Capture error: {e}")
        finally:
            if os.name == 'nt':
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sniffer.close()
            
        self.show_statistics()
    
    def process_packet(self, data):
        """Process individual packet"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        try:
            # Parse Ethernet frame
            dest_mac, src_mac, eth_proto, data = self.ethernet_frame(data)
            
            # IPv4 packets
            if eth_proto == 8:
                version, header_length, ttl, proto, src_ip, dest_ip, data = self.ipv4_packet(data)
                protocol_name = self.protocol_name(proto)
                
                src_port = dest_port = None
                flags = None
                
                # TCP
                if proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flags, data = self.tcp_segment(data)
                    flags = self.tcp_flags(flags)
                
                # UDP
                elif proto == 17:
                    src_port, dest_port, length, data = self.udp_segment(data)
                
                # ICMP
                elif proto == 1:
                    icmp_type, code, checksum, data = self.icmp_packet(data)
                    src_port = f"ICMP({icmp_type})"
                    dest_port = f"Code({code})"
                
                self.display_packet_info(timestamp, protocol_name, src_ip, dest_ip, src_port, dest_port, flags, data)
                
        except Exception as e:
            print(f"❌ Packet processing error: {e}")
    
    def show_statistics(self):
        """Display capture statistics"""
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"\n📊 CAPTURE STATISTICS")
            print(f"📦 Total Packets: {self.packet_count}")
            print(f"⏱️  Duration: {duration:.2f} seconds")
            if duration > 0:
                print(f"📈 Packets/second: {self.packet_count/duration:.2f}")
    
    def run(self):
        """Main application loop"""
        while True:
            self.main_menu()
            choice = input("\nChoose option (1-4): ").strip()
            
            if choice == "1":
                try:
                    count = int(input("Enter number of packets to capture (default 50): ") or "50")
                    timeout = int(input("Enter timeout in seconds (default 30): ") or "30")
                    self.start_capture(count, timeout)
                except ValueError:
                    print("❌ Please enter valid numbers!")
                    
            elif choice == "2":
                self.show_statistics()
                
            elif choice == "3":
                os.system('cls' if os.name == 'nt' else 'clear')
                
            elif choice == "4":
                print("👋 Goodbye! Remember to use this tool ethically!")
                break
                
            else:
                print("❌ Invalid choice! Please enter 1-4.")

def main():
    # Check platform and permissions
    if os.name != 'nt' and os.geteuid() != 0:
        print("❌ Root privileges required on Unix systems!")
        print("💡 Run with: sudo python packet_analyzer.py")
        return
    
    print("🔍 NETWORK PACKET ANALYZER - EDUCATIONAL USE ONLY")
    print("="*50)
    print("⚠️  LEGAL NOTICE:")
    print("   - Only use on networks you own")
    print("   - Get proper authorization")
    print("   - Respect privacy laws")
    print("   - Educational purposes only")
    print("="*50)
    
    confirm = input("Do you understand and agree? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ Agreement required to proceed.")
        return
    
    analyzer = NetworkPacketAnalyzer()
    analyzer.run()

if __name__ == "__main__":
    main()