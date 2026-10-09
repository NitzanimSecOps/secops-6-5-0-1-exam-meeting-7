"""selftest.py — run your switch locally while you work on the exam.

    python selftest.py          # runs the one example below
    VS Code: open this file, press F5 (Run and Debug), set breakpoints in switch.py.

No real network is needed: this fakes the raw sockets so your Switch constructs anywhere.
Use arp_frame()/eth_frame() to build frames, and send() to push one into your switch and
see what it printed and where it forwarded.

Only a harness is provided here — the exam is about deciding WHICH frames are malicious and
building the cases to prove it. Add your own frames below and check your switch's behaviour.
"""
import socket
import struct

from switch import Switch   # your solution (bring switch.py + ethernet.py + your ARP parser arp.py)

PORTS = ["p_gw", "p_victim", "p_attacker"]   # referenced by index (0,1,2), matching this order
BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO = "00:00:00:00:00:00"


def _mac(m):
    return bytes.fromhex(m.replace(":", ""))


def _ip(ip):
    return bytes(int(o) for o in ip.split("."))


def arp_frame(opcode, sender_ip, sender_mac, target_ip, *, eth_dst=BROADCAST,
              eth_src=None, target_mac=ZERO):
    """Build an Ethernet+ARP frame. opcode 1 = request, 2 = reply. eth_src defaults to the
    ARP sender MAC — pass a different one to forge the Ethernet header."""
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, opcode,
                      _mac(sender_mac), _ip(sender_ip), _mac(target_mac), _ip(target_ip))
    return _mac(eth_dst) + _mac(eth_src or sender_mac) + struct.pack("!H", 0x0806) + arp


def eth_frame(src_mac, dst_mac=BROADCAST, ethertype=0x0800, payload=b"hi"):
    """Build a plain (non-ARP) Ethernet frame."""
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype) + payload


class _FakeSock:
    def __init__(self, *a, **k):
        self.sent = []

    def bind(self, *a, **k):
        pass

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def setsockopt(self, *a, **k):
        pass

    def close(self):
        pass


def new_switch():
    """A Switch whose ports use fake sockets, so it runs with no real interfaces."""
    for name, val in (("AF_PACKET", 17), ("SOCK_RAW", 3)):
        if not hasattr(socket, name):
            setattr(socket, name, val)
    if not hasattr(socket, "htons"):
        socket.htons = lambda x: x
    socket.socket = lambda *a, **k: _FakeSock()
    return Switch(PORTS)


def send(sw, frame, port_index, label=""):
    """Send one frame into the switch on a port (by index), and show what happened."""
    before = [len(p.sock.sent) for p in sw.ports]
    print(f"\n>>> {label or 'send'}  (in on port {port_index} = {PORTS[port_index]})")
    sw._process_frame(frame, sw.ports[port_index])     # <-- your code runs here; breakpoint it
    forwarded = [PORTS[i] for i, p in enumerate(sw.ports) if len(p.sock.sent) > before[i]]
    print(f"    forwarded to: {forwarded or 'nobody (dropped)'}")


if __name__ == "__main__":
    sw = new_switch()

    # One ordinary frame to show the harness. The gateway asks who has the victim.
    send(sw, arp_frame(1, "10.0.0.1", "02:00:00:00:00:01", "10.0.0.2"), 0, "a normal ARP request")

    # TODO: build the frames YOU think a switch should flag, send() them, and confirm your
    # switch prints ARP-POISONING and drops only those — while leaving honest traffic alone.
