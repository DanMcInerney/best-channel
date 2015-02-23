
#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Shut up Scapy
from scapy.all import *
conf.verb = 0 # Scapy I thought I told you to shut up
import os
import sys
import time
from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import SIGINT, signal
import argparse
import socket
import struct
import fcntl

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

channels = {}

def parse_args():
	#Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Choose monitor mode interface. By default script \
                        will find the most powerful interface and starts monitor mode on it. Example: -i mon5")
    return parser.parse_args()

########################################
# Begin interface info and manipulation
########################################

def get_mon_iface(args):
    global monitor_on
    monitors, interfaces = iwconfig()
    if args.interface:
        monitor_on = True
        return args.interface
    if len(monitors) > 0:
        monitor_on = True
        return monitors[0]
    else:
        # Start monitor mode on a wireless interface
        print '['+G+'*'+W+'] Finding the most powerful interface...'
        interface = get_iface(interfaces)
        monmode = start_mon_mode(interface)
        return monmode

def iwconfig():
    monitors = []
    interfaces = {}
    proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Isn't an empty string
        if line[0] != ' ': # Doesn't start with space
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search: # Isn't wired
                iface = line[:line.find(' ')] # is the interface
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    return monitors, interfaces

def get_iface(interfaces):
    scanned_aps = []

    if len(interfaces) < 1:
        sys.exit('['+R+'-'+W+'] No wireless interfaces found, bring one up and try again')
    if len(interfaces) == 1:
        for interface in interfaces:
            return interface

    # Find most powerful interface
    for iface in interfaces:
        count = 0
        proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            if ' - Address:' in line: # first line in iwlist scan for a new AP
               count += 1
        scanned_aps.append((count, iface))
        print '['+G+'+'+W+'] Networks discovered by '+G+iface+W+': '+T+str(count)+W
    try:
        interface = max(scanned_aps)[1]
        return interface
    except Exception as e:
        for iface in interfaces:
            interface = iface
            print '['+R+'-'+W+'] Minor error:',e
            print '    Starting monitor mode on '+G+interface+W
            return interface

def start_mon_mode(interface):
    print '['+G+'+'+W+'] Starting monitor mode off '+G+interface+W
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode monitor' % interface)
        os.system('ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('['+R+'-'+W+'] Could not start monitor mode')

def remove_mon_iface(mon_iface):
    os.system('/sbin/ifconfig %s down' % mon_iface)
    os.system('/sbin/iwconfig %s mode managed' % mon_iface)
    os.system('/sbin/ifconfig %s up' % mon_iface)

def mon_mac(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    print '['+G+'*'+W+'] Monitor mode: '+G+mon_iface+W+' - '+O+mac+W
    return mac

########################################
# End of interface info and manipulation
########################################


def cb(pkt):
    '''
    Look for dot11 packets that aren't to or from broadcast address,
    are type 1 or 2 (control, data), and append the addr1 and addr2
    to the list of deauth targets.
    '''
    # We're adding the AP and channel to the deauth list at time of creation rather
    # than updating on the fly in order to avoid costly for loops that require a lock
    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:

            # Check if it's added to our AP list
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs(pkt)

def APs(pkt):
    ssid       = pkt[Dot11Elt].info
    bssid      = pkt[Dot11].addr3
    try:
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']
        if ap_channel in chans:
            print ap_channel
    except Exception as e:
        raise

def output(err, monchannel):
    os.system('clear')
    if err:
        print err
    else:
        print '['+G+'+'+W+'] '+mon_iface+' channel: '+G+monchannel+W+'\n'

def channel_hop(mon_iface):
    '''
    First time it runs through the channels it stays on each channel for 5 seconds
    in order to populate the deauth list nicely. After that it goes as fast as it can
    '''
    global monchannel

    channelNum = 0
    maxChan = 11
    err = None

    while 1:
        channelNum +=1
        if channelNum > maxChan:
            channelNum = 1
        monchannel = str(channelNum)

        try:
            proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', monchannel], stdout=DN, stderr=PIPE)
        except OSError:
            print '['+R+'-'+W+'] Could not execute "iw"'
            os.kill(os.getpid(),SIGINT)
            sys.exit(1)
        for line in proc.communicate()[1].split('\n'):
            if len(line) > 2: # iw dev shouldnt display output unless there's an error
                err = '['+R+'-'+W+'] Channel hopping failed: '+R+line+W
        time.sleep(.5)

        output(err, monchannel)

def stop(signal, frame):
    if monitor_on:
        sys.exit('\n['+R+'!'+W+'] Closing')
    else:
        remove_mon_iface(mon_iface)
        sys.exit('\n['+R+'!'+W+'] Closing')

if __name__ == "__main__":
    if os.geteuid():
        sys.exit('['+R+'-'+W+'] Please run as root')
    args = parse_args()
    DN = open(os.devnull, 'w')
    monitor_on = None
    mon_iface = get_mon_iface(args)
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)

    hop = Thread(target=channel_hop, args=(mon_iface,))
    hop.daemon = True
    hop.start()

    signal(SIGINT, stop)

    try:
       sniff(iface=mon_iface, store=0, prn=cb)
    except Exception as msg:
        remove_mon_iface(mon_iface)
        print '\n['+R+'!'+W+'] Sniffing failed, closing'
        sys.exit(0)
