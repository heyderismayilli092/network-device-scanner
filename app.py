from flask import Flask, render_template
from scapy.all import ARP, Ether, srp
import socket
import fcntl
import struct
import psutil

app = Flask(__name__)

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(
        fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24]
    )
def find_active_interface():  # Find the active network interface
    # Get all network interfaces
    interfaces = psutil.net_if_addrs()
    candidates = list(interfaces.keys())
    # Get Wifi and Ethernet network interfaces
    wifi_candidates = [i for i in candidates if i.startswith(("wlo", "wlan", "wlp"))]
    eth_candidates = [i for i in candidates if i.startswith(("eth", "eno", "enp"))]
    # Filters those with active IP addresses
    def get_valid_ip(ifname):
        for addr in interfaces.get(ifname, []):
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):  # Those with IPv4 addresses and non-local network addresses are being returned.
                return addr.address
        return None
    # Check Wi-Fi
    for ifname in wifi_candidates:
        ip = get_valid_ip(ifname)
        if ip:
          return ifname
    # Check Ethernet
    for ifname in eth_candidates:
        ip = get_valid_ip(ifname)
        if ip:
          return ifname
    return None


# index
@app.route("/")
def index():
    iface = find_active_interface()  # get active network interface
    if iface == None:
      return render_template("index.html", find_devices="notconnect")  # If this function returns None, it means the device is not connected to any network
    else:
      return render_template("index.html", find_devices="", ninterface=iface)

# scan network
@app.route("/scan")
def scanning():
  pck_eth = Ether()  # create Ethernet frame
  pck_arp = ARP()  # create ARP package
  pck_eth.dst = "ff:ff:ff:ff:ff:ff"
  pck_arp.pdst = "192.168.1.0/24"  # Specifies the destination IP range for the ARP packet (for home modems only).
  pack_brdc = pck_eth/pck_arp  # Ethernet + ARP
  ans, unans = srp(pack_brdc, timeout=5)  # ARP broadcast packets send with Layer 2
  find_devices = []  # create find devices list
  for send, recv in ans:
    find_devices.append((recv.psrc, recv.hwsrc))  # The IP and MAC addresses of the found devices are added to the list in tuple format
  if len(find_devices) == 0:
    return render_template("index.html", find_devices=None)
  else:
    return render_template("index.html", find_devices=find_devices)

if __name__ == "__main__":
    app.run(port=2505, debug=False)
