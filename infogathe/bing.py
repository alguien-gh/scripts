#!/usr/bin/env python
import urllib
import urllib2
import re
import socket
import argparse
from urlparse import urlparse
from HTMLParser import HTMLParser


class BingDorker(object):
    def __init__(self, cookie=None, agent=None):
        self.link_pattern = re.compile('<h2><a href="([^"]*)" h="[^"]*">[^<]*</a></h2>')
        self.search_url = 'https://www.bing.com/search'
        self.agent = agent if agent is not None else 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Firefox/52.0'

    def search(self, dork='site:example.com', start=1, num=50):
        num = 50 if num > 50 else num
        try:
            req = urllib2.Request(
                '%s?%s' % (self.search_url, urllib.urlencode({
                    'q': dork,
                    'first': start
                })),
                None,
                {'User-Agent': self.agent, 'Cookie': 'SRCHHPGUSR=NRSLT={};'.format(num)}
            )
            desc = urllib2.urlopen(req)
            html = desc.read()
            desc.close()
        except urllib2.URLError as err:
            print 'error:', err
            return None
        html_parser = HTMLParser()
        return [html_parser.unescape(link.decode('utf8')) for link in self.link_pattern.findall(html)]

class NameSearcher(object):
    def __init__(self, basename, dorker=None):
        self.basename = basename
        self.dorker = dorker if dorker is not None else BingDorker()

    def gen_dork(self, names=[]):
        names = [_ for _ in names if _ != self.basename]
        return "site:{} ".format(self.basename) + ' '.join(["-site:{}".format(name) for name in names])

    def search_names(self, npages=5):
        names = []
        keep = True
        while keep:
            keep = False
            dork = self.gen_dork(names)
            for npage in xrange(npages):
                urls = self.dorker.search(dork, npage * 50 + 1, 50)
                if urls is None:
                    return names
                for url in urls:
                    name = urlparse(url).hostname
                    if name is not None and name not in names:
                        print "[+] {}".format(name)
                        names.append(name)
                        keep = True
        return names


class IPSearcher(object):
    def __init__(self, ipaddr, dorker=None):
        self.ipaddr = ipaddr
        self.dorker = dorker if dorker is not None else BingDorker()

    def search_names(self, npages=10):
        names = []
        dork = 'ip:{}'.format(self.ipaddr)
        for npage in xrange(npages):
            urls = self.dorker.search(dork, npage * 50 + 1, 50)
            if urls is None:
                return names
            for url in urls:
                name = urlparse(url).hostname
                if name is not None and name not in names:
                    print "[+] {}".format(name)
                    names.append(name)
        return names


def main():
    parser = argparse.ArgumentParser(description='Search Subdomains.')
    parser.add_argument('domain', metavar='DOMAIN|IPADDR', type=str, help='The domain name. E.g.: example.com')
    parser.add_argument('-r', '--reverse', action='store_true', help='Bing reverse domain resolution.')
    parser.add_argument('-a', '--agent', metavar='AGENT', type=str, help='User-Agent string. E.g.: Mozilla/5.0')
    args = parser.parse_args()

    dorker = BingDorker(agent=args.agent)
    searcher = IPSearcher(args.domain, dorker=dorker) if args.reverse else NameSearcher(args.domain, dorker=dorker)
    names = searcher.search_names()

    print '[+] Total found: {}'.format(len(names))
    maxlen = str(max([len(_) for _ in names])) if len(names) > 0 else None
    for name in names:
        try:
            _, _, addrs = socket.gethostbyname_ex(name)
            for addr in addrs:
                print ('{:>' + maxlen + '}\t{}').format(name, addr)
        except:
            print ('{:>' + maxlen + '}\t{}').format(name, 'unknown')


if __name__ == "__main__":
    main()
