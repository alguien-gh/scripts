#!/usr/bin/env python
'''
License: Free as in free beer
Author: Alguien (@alguien_tw) | alguien.site
Support: devnull@alguien.site
'''
from scapy.all import *
from random import random
import socket
import struct
import argparse
import os

# Top 10 TCP ports from nmap-services
TOP_PORTS = [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139]

# Global config
CONFIG = {
    'timeout': 5,
    'min_ttl': 1,
    'max_ttl': 20,
    'max_deep': 3,
    'max_mask': 22,
    'mask': 29,
    'scan': True,
    'target': '0.0.0.0',
    'verb': 3
}

COLORS = {
    'red': '\033[0;31m',
    'red-bold': '\033[1;31m',
    'green': '\033[0;32m',
    'green-bold': '\033[1;32m',
    'yellow': '\033[0;33m',
    'yellow-bold': '\033[1;33m',
    'blue': '\033[0;34m',
    'blue-bold': '\033[1;34m',
    'endc': '\033[0m'
}


def print_msg(msg, color='blue', verb=3):
    if verb <= CONFIG['verb']:
        if color not in COLORS:
            color = 'blue'
        print "%s%s%s" % (COLORS[color], msg, COLORS['endc'])


def unsort_list(lst):
    return sorted(lst, key=lambda x: random())


def random_ip(base_ip, mask):
    return Net('%s/%d' % (base_ip, mask)).choice()


def inet_aton(str_ip):
    return struct.unpack('!L', socket.inet_aton(str_ip))[0]


def inet_ntoa(lng_ip):
    return socket.inet_ntoa(struct.pack('!L', lng_ip))


def to_net(ip, mask):
    net = inet_aton(ip) & ((~0) << (32 - mask))
    return inet_ntoa(net)


def comp_subnet(ip, mask):
    net = to_net(ip, mask)
    numb = inet_aton(net) ^ (1 << (32 - mask))
    return inet_ntoa(numb)


def div_net(net, mask, limit):
    net = to_net(net, mask)
    if mask < limit:
        mask += 1
        net2 = comp_subnet(net, mask)
        return div_net(net, mask, limit) + div_net(net2, mask, limit)
    else:
        return [{'ip': net, 'mask': mask}]


def find_gateway(path1, path2):
    max_deep = CONFIG['max_deep']
    if len(path1) < 2 or len(path2) < 2:
        return None
    gws = []
    dst1 = path1[-1]
    dst2 = path2[-1]
    idx1 = len(path1) - 2
    while idx1 >= 0:
        hop1 = path1[idx1]
        if dst1['ttl'] - hop1['ttl'] > max_deep:
            break
        idx2 = len(path2) - 2
        while idx2 >= 0:
            hop2 = path2[idx2]
            if dst2['ttl'] - hop2['ttl'] > max_deep:
                break
            if hop1['ip'] == hop2['ip']:
                gws.append({'path1': hop1, 'path2': hop2})
            idx2 -= 1
        idx1 -= 1
    if len(gws) == 0:
        return None
    major = gws[0]
    major_val = (
        (dst1['ttl'] - major['path1']['ttl']) +
        (dst2['ttl'] - major['path2']['ttl']) +
        abs(major['path1']['ttl'] - major['path2']['ttl']))
    for idx in range(1, len(gws)):
        gw = gws[idx]
        val = (
            (dst1['ttl'] - gw['path1']['ttl']) +
            (dst2['ttl'] - gw['path2']['ttl']) +
            abs(gw['path1']['ttl'] - gw['path2']['ttl']))
        if val < major_val:
            major = gw
            major_val = val
    if major['path1']['ttl'] == major['path2']['ttl']:
        major = major['path1']
    elif major['path1']['ttl'] > major['path2']['ttl']:
        major = major['path1']
    else:
        major = major['path2']
    return major


def port_scan(target_ip, dest_port):
    pkt = IP(dst=target_ip) / TCP(sport=RandShort(), dport=dest_port, flags="S")
    ans, _ = sr(pkt, timeout=CONFIG['timeout'], verbose=False)
    hosts = []
    for (snd, rcv) in ans:
        if TCP in rcv and rcv[TCP].flags & 0x02 and rcv[TCP].flags & 0x10:  # flags: 0x02 SYN / 0x10 ACK
            hosts.append({'ip': snd.dst, 'port': snd[TCP].dport})
    return hosts


def trace_route(target_ip, dest_port):
    ans, _ = traceroute(target_ip, dport=dest_port, minttl=CONFIG['min_ttl'], maxttl=CONFIG['max_ttl'],
                        timeout=CONFIG['timeout'], verbose=False)
    path = []
    for (snd, rcv) in ans:
        path.append({'ttl': snd.ttl, 'ip': rcv.src})
    if len(path) > 0:
        path = sorted(path, key=lambda x: x['ttl'])  # sort by TTL
        ip_addrs = [x['ip'] for x in path]
        if target_ip in ip_addrs:
            path = path[:ip_addrs.index(target_ip) + 1]  # remove repeated target_ip entries
    return path


def parse_args():
    global CONFIG
    print '''
'########'########::::'###::::'######:'########'##::: ##'########'########:
... ##..::##.... ##::'## ##::'##... ##:##.....::###:: ##:##.....:... ##..::
::: ##::::##:::: ##:'##:. ##::##:::..::##:::::::####: ##:##::::::::: ##::::
::: ##::::########:'##:::. ##:##:::::::######:::## ## ##:######::::: ##::::
::: ##::::##.. ##:::#########:##:::::::##...::::##. ####:##...:::::: ##::::
::: ##::::##::. ##::##.... ##:##::: ##:##:::::::##:. ###:##::::::::: ##::::
::: ##::::##:::. ##:##:::: ##. ######::########:##::. ##:########::: ##::::
:::..::::..:::::..:..:::::..::......::........:..::::..:........::::..:::::
'''
    parser = argparse.ArgumentParser(
        description='A tool for network range discovery using traceroute.',
        epilog='Author: Alguien (@alguien_tw) | alguien.site')
    parser.add_argument('ip', metavar='IP', type=str, help='Any IP address in the target network')
    parser.add_argument('--mask', type=int, help='Initial netmask')
    parser.add_argument('--max-mask', type=int, help='Maximum netmask to try')
    parser.add_argument('--timeout', type=int, help='Timeout for portscan and traceroute')
    parser.add_argument('--min-ttl', type=int, help='Minimum TTL for traceroute')
    parser.add_argument('--max-ttl', type=int, help='Maximum TTL for traceroute')
    parser.add_argument('--deep', type=int, help='Maximum deep for finding a common hop')
    parser.add_argument('--no-scan', action='store_true', default=False, help='Don\'t perform portscan')
    parser.add_argument('--verb', type=int, help='Verbose level [1-3]')
    args = parser.parse_args()

    # update global config
    if args.max_mask is not None:
        CONFIG['max_mask'] = args.max_mask
    if args.timeout is not None:
        CONFIG['timeout'] = args.timeout
    if args.min_ttl is not None:
        CONFIG['min_ttl'] = args.min_ttl
    if args.max_ttl is not None:
        CONFIG['max_ttl'] = args.max_ttl
    if args.deep is not None:
        CONFIG['max_deep'] = args.deep
    if args.mask is not None:
        CONFIG['mask'] = args.mask
    if args.no_scan:
        CONFIG['scan'] = False
    if args.verb is not None:
        CONFIG['verb'] = args.verb
    CONFIG['target'] = args.ip


def print_route(dest, path):
    msg = "[*] Route to %s:" % (dest['ip'])
    print_msg(msg, 'blue', 3)
    for hop in path:
        msg = "\t%3d: %s" % (hop['ttl'], hop['ip'])
        print_msg(msg, 'blue', 3)


def search_hosts(net, mask):
    scan = CONFIG['scan']
    hosts = []
    subnets = div_net(net, mask, 26)
    subnets = unsort_list(subnets)
    if scan:
        msg = "[*] Scanning network %s/%d..." % (net, mask)
        print_msg(msg, 'blue', 2)
        for port in TOP_PORTS:
            msg = "\t> Trying with port %d..." % (port)
            print_msg(msg, 'blue', 3)
            for sub in subnets:
                hosts = port_scan('%s/%d' % (sub['ip'], sub['mask']), port)
                if len(hosts) > 0:
                    return hosts
    host = {'ip': random_ip(net, mask), 'port': 80}
    hosts.append(host)
    msg = "[*] Using a random IP (%s:%d)" % (host['ip'], host['port'])
    print_msg(msg, 'blue', 2)
    return hosts


def main():
    parse_args()

    if os.getuid() != 0:
        msg = "[-] Error. Root privileges is required."
        print_msg(msg, 'red-bold', 1)
        exit(-1)

    mask = CONFIG['mask']
    max_mask = CONFIG['max_mask']
    target = CONFIG['target']

    net = to_net(target, mask)
    hosts = unsort_list(search_hosts(net, mask))
    dest = hosts.pop()

    msg = "[*] Host found: %s:%d" % (dest['ip'], dest['port'])
    print_msg(msg, 'green', 1)

    paths = []

    path = trace_route(dest['ip'], dest['port'])
    if len(path) == 0:
        msg = "[-] Error. I can't trace the route to %s" % (dest['ip'])
        print_msg(msg, 'red-bold', 1)
        exit(-1)

    print_route(dest, path)

    paths.append({'dest': dest, 'path': path})

    while mask > max_mask:
        hosts = unsort_list(search_hosts(comp_subnet(net, mask), mask))
        dest = hosts.pop()

        msg = "[*] Host found: %s:%d" % (dest['ip'], dest['port'])
        print_msg(msg, 'green', 1)

        path = trace_route(dest['ip'], dest['port'])
        if len(path) == 0:
            msg = "[-] Error. I can't trace the route to %s" % (dest['ip'])
            print_msg(msg, 'red-bold', 1)
            break

        print_route(dest, path)

        for prev in paths:
            gateway = find_gateway(prev['path'], path)
            if gateway is None:
                msg = "[*] There is not a common hop for %s and %s" % (prev['dest']['ip'], dest['ip'])
                print_msg(msg, 'yellow', 2)
            else:
                msg = "[+] Common hop found between %s and %s: %s (ttl: %d)" % (prev['dest']['ip'], dest['ip'], gateway['ip'], gateway['ttl'])
                print_msg(msg, 'green', 2)
                break

        if gateway is None:
            msg = "[*] Common hops not found"
            print_msg(msg, 'red-bold', 1)
            break

        paths.append({'dest': dest, 'path': path})

        mask -= 1
        net = to_net(net, mask)

        msg = "[+] Current network range: %s/%d" % (net, mask)
        print_msg(msg, 'green-bold', 1)

    msg = "[+] Network range: %s/%d" % (net, mask)
    print_msg(msg, 'green-bold', 1)


if __name__ == '__main__':
    main()
