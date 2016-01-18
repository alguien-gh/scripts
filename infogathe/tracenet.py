#!/usr/bin/env python

from scapy.all import *
import argparse


# Top 10 TCP ports from nmap-services
TOP_PORTS = [80, 23, 443, 21, 22, 25, 3389, 110, 445, 139]

# Global config
CONFIG = {
    'timeout': 5,
    'min_ttl': 1,
    'max_ttl': 20,
    'max_deep': 3,
    'max_mask': 22
}


def to_numb(ip):
    ip = [int(x) for x in ip.split('.')]
    return sum([ip[3 - n] * (256 ** n) for n in range(0, 4)])


def to_ip(numb):
    ip = []
    for n in range(0, 4):
        div = 256 ** (3 - n)
        ip.append(str(numb / div))
        numb = numb % div
    return '.'.join(ip)


def to_net(ip, mask):
    numb = to_numb(ip)
    net = numb & ((~0) << (32 - mask))
    return to_ip(net)


def comp_subnet(ip, mask):
    net = to_net(ip, mask)
    numb = to_numb(net)
    numb = numb ^ (1 << (32 - mask))
    return to_ip(numb)


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


def portscan(ip, port):
    timeout = CONFIG['timeout']
    hosts = []
    pkt = IP(dst=ip) / TCP(sport=RandShort(), dport=port, flags="S")
    ans, unans = sr(pkt, timeout=timeout, verbose=False)
    for (snd, rcv) in ans:
        if TCP in rcv:
            flags = rcv[TCP].flags
            if flags & 0x02 and flags & 0x10:    # flags: 0x02 SYN / 0x10 ACK
                hosts.append({'ip': snd.dst, 'port': snd[TCP].dport})
    return hosts


def traceroute(ip, port):
    timeout = CONFIG['timeout']
    minttl = CONFIG['min_ttl']
    maxttl = CONFIG['max_ttl']
    path = []
    pkt = IP(dst=ip, ttl=(minttl, maxttl), id=RandShort())
    pkt = pkt / TCP(sport=RandShort(), dport=port, flags='S')
    ans, unans = sr(pkt, timeout=timeout, verbose=False)
    for (snd, rcv) in ans:
        path.append({'ttl': snd.ttl, 'ip': rcv.src})
    if len(path) > 0:
        path = sorted(path, key=lambda x: x['ttl'])
        try:
            idx = [x['ip'] for x in path].index(ip)
            path = path[:idx + 1]
        except:
            path = []
    return path


def parse_args():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('ip', metavar='IP', type=str)
    parser.add_argument('--mask', type=int, default=29)
    parser.add_argument('--max-mask', type=int)
    parser.add_argument('--timeout', type=int)
    parser.add_argument('--min-ttl', type=int)
    parser.add_argument('--max-ttl', type=int)
    parser.add_argument('--deep', type=int)
    return parser.parse_args()


def main():
    global CONFIG
    args = parse_args()

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

    ip = args.ip
    mask = args.mask
    max_mask = CONFIG['max_mask']

    net = to_net(ip, mask)
    print "Escaneando subnet %s/%d..." % (net, mask)

    hosts = []
    for port in TOP_PORTS:
        print "Escaneando puerto %d" % (port)
        hosts += portscan('%s/%d' % (net, mask), port)
        if len(hosts) > 0:
            break

    if len(hosts) == 0:
        print "No hay suficientes resultados en el escaneo"
        exit()

    print "Resultados: "
    for host in hosts:
        print host

    dest1 = hosts[0]
    path1 = traceroute(dest1['ip'], dest1['port'])

    while mask > max_mask:
        net2 = comp_subnet(net, mask)
        print "Escaneando subnet %s/%s..." % (net2, mask)

        hosts = []
        for port in TOP_PORTS:
            print "Escaneando puerto %d" % (port)
            hosts += portscan('%s/%s' % (net2, mask), port)
            if len(hosts) > 0:
                break

        if len(hosts) == 0:
            print "No hay suficientes resultados en el escaneo"
            break

        print "Resultados: "
        for host in hosts:
            print host

        dest2 = hosts[0]
        path2 = traceroute(dest2['ip'], dest2['port'])

        gateway = find_gateway(path1, path2)
        if gateway is None:
            print "No se encontro un gateway comun"
            break

        print "Gateway: %s (ttl: %d)" % (gateway['ip'], gateway['ttl'])
        mask -= 1
        net = to_net(net, mask)

    print "Network: %s/%d" % (to_net(ip, mask), mask)


if __name__ == '__main__':
    main()
