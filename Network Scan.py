import os
import platform

try:
    import scapy.all as scapy
except ImportError:
    raise ImportError("Unable to import scapy. Please make sure it is installed") from None

if not os.environ.get("SUDO_UID"):
    raise PermissionError("You need to run this script with sudo.")


class Devices:
    def __init__(self, router_ip_addr):
        self.devices = []
        self.router_ip_addr = router_ip_addr

    def add_device(self, ip, mac):
        is_router = True if ip == self.router_ip_addr else False
        device = [ip, mac, is_router]
        if device not in self.devices:
            self.devices.append(device)


def user_input(message):
    try:
        input_val = int(input(message))
        if input_val >= 1:
            return input_val
        else:
            print("\033[A" + "\033[K", end='')
            return user_input('Please enter a valid value: ')
    except ValueError:
        print("\033[A" + "\033[K", end='')
        return user_input('Please enter a valid value: ')


router_ip = scapy.conf.route.route("0.0.0.0")[2]

print('---------------Network Scanner---------------')
if platform.system() != 'Linux':
    print(f"This program is designed to run on Linux. Your OS is {platform.system()}")
print(f'Router ip is: {router_ip}')
print(f'Network interface is: {scapy.conf.iface}')
print('---------------------------------------------')

# -----------Creating ARP package------------
request = scapy.ARP()
request.pdst = f'{router_ip}/24'
broadcast = scapy.Ether()
broadcast.dst = 'ff:ff:ff:ff:ff:ff'
request_broadcast = broadcast / request
# -----------Creating ARP package------------


print('How many times will the scanner run?')
print('A value of 25 should be enough. You can use a higher value to ensure that the program detects all devices connected to the network.')
scan_duration = user_input('Specify Scanner Duration: ')
print("\033[A" + "\033[K", end='')
print("\033[A" + "\033[K", end='')
print("\033[A" + "\033[K", end='')

found_devices = Devices(router_ip)

for i in range(1, scan_duration + 1):
    print(f'Times Scanned:{i}/{scan_duration}', end='\r')
    clients = scapy.srp(request_broadcast, timeout=0.1, inter=0.001, verbose=0)[0]
    for element in clients:
        found_devices.add_device(element[1].psrc, element[1].hwsrc)

print('----------------Found Devices----------------')

for num, i in enumerate(found_devices.devices, start=1):
    print(f'Device No:{num} | Ip: {i[0]} | Mac: {i[1]} | {"Router" if i[2] else ""}')
