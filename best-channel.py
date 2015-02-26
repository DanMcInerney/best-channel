
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

channels = {1:{}, 6:{}, 11:{}}

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
    print '['+G+'+'+W+'] Starting monitor mode on '+G+interface+W
    try:
        os.system('/sbin/ifconfig %s down' % interface)
        os.system('/sbin/iwconfig %s mode monitor' % interface)
        os.system('/sbin/ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('['+R+'-'+W+'] Could not start monitor mode')
        raise ####################

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
    ssid = pkt[Dot11Elt].info
    bssid = pkt[Dot11].addr3
    try:
        chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']
        # http://stackoverflow.com/questions/10818661/scapy-retrieving-rssi-from-wifi-packets
        sig_str = -(256-ord(pkt.notdecoded[-4:-3]))
        # airoscapy
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        if ap_channel in chans:
            if ap_channel in ['1','2','3']:
                # Set to {MAC address:avg power signal}
                if bssid in channels[1]:
                    channels[1][bssid].append(sig_str)
                else:
                    channels[1][bssid] = [sig_str]
            elif ap_channel in ['4','5','6','7','8']:
                # Set to {MAC address:avg power signal}
                if bssid in channels[6]:
                    channels[6][bssid].append(sig_str)
                else:
                    channels[6][bssid] = [sig_str]
            elif ap_channel in ['9', '10', '11']:
                # Set to {MAC address:avg power signal}
                if bssid in channels[11]:
                    channels[11][bssid].append(sig_str)
                else:
                    channels[11][bssid] = [sig_str]
    except Exception:
        raise

def output(err, num_aps, chan_interference, best_channel):
    os.system('clear')
    if err:
        print err
    else:
        print '[Channels '+G+'1-3'+W+']  Number of APs: '+T+'%d' % num_aps[1], W+' |  Interference level: '+R+'%d' % chan_interference[1], W
        print '[Channels '+G+'4-8'+W+']  Number of APs: '+T+'%d' % num_aps[6], W+' |  Interference level: '+R+'%d' % chan_interference[6], W
        print '[Channels '+G+'9-11'+W+'] Number of APs: '+T+'%d' % num_aps[11], W+' |  Interference level: '+R+'%d' % chan_interference[11], W
        print '['+G+'+'+W+'] Recommended channel: '+G+'%s' % best_channel, W

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

        # avg_pwr_per_ap = {1:{bssid:ap_pwr}, 6:[...], 11:[...]}
        avg_pwr_per_ap = get_ap_pwr()
        num_aps = get_num_aps(avg_pwr_per_ap)
        chan_interference = get_chan_interference(avg_pwr_per_ap)
        best_channel = get_best_channel(chan_interference)

        output(err, num_aps, chan_interference, best_channel)
        time.sleep(.5)

def get_best_channel(chan_interference):
    '''
    Get the channel with the least interference
    '''
    if chan_interference[1] == chan_interference[6] == chan_interference[11]:
        return 'All the same'

    least = min([chan_interference[1], chan_interference[6], chan_interference[11]])
    if least == chan_interference[1]:
        return '1'
    elif least == chan_interference[6]:
        return '6'
    elif least == chan_interference[11]:
        return '11'

def get_chan_interference(avg_pwr_per_ap):
    '''
    Add together all the BSSID's avg pwr levels
    '''
    interference_val = {1:0, 6:0, 11:0}
    total_power = {1:[], 6:[], 11:[]}
    for chan in [1, 6, 11]:
        for bssid in avg_pwr_per_ap[chan]:
            total_power[chan].append(avg_pwr_per_ap[chan][bssid])
        interference_val[chan] = -sum(total_power[chan])

    return interference_val

def get_ap_pwr():
    '''
    Returns a dict of nonoverlapping channels which contains
    a dict of each BSSID's average power
    '''
    avg_pwr_per_ap = {1:{}, 6:{}, 11:{}}
    for chan in [1, 6, 11]:
        # channels[chan] = {'bssid':[avgpwr, avgpwr]}
        for bssid in channels[chan]:
            bssid_avg_pwr = float(sum(channels[chan][bssid]))/len(channels[chan][bssid]) if len(channels[chan][bssid]) > 0 else 0
            avg_pwr_per_ap[chan][bssid] = bssid_avg_pwr

    return avg_pwr_per_ap

def get_num_aps(avg_pwr_per_ap):

    num_aps = {1:0, 6:0, 11:0}
    for chan in [1, 6, 11]:
        num_aps[chan] = len(avg_pwr_per_ap[chan])
    return num_aps

def stop(signal, frame):
    if monitor_on:
        sys.exit(
        '\n['+R+'!'+W+'] Closing... You will probably have to reconnect to your \
wireless network if you were on one prior to running this script')
    else:
        remove_mon_iface(mon_iface)
        sys.exit('\n['+R+'!'+W+'] Closing... You will probably have to reconnect to your \
wireless network if you were on one prior to running this script')

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
        print '\n['+R+'!'+W+'] Sniffing failed: %s' % str(msg)
        sys.exit(0)
