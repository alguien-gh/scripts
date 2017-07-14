#!/usr/bin/env python
import urllib
import urllib2
import re
import socket
import argparse
from urlparse import urlparse
from HTMLParser import HTMLParser


class GoogleDorker(object):
    def __init__(self, cookie=None, agent=None):
        self.link_pattern = re.compile('<h3 class="r"><a href="([^"]+)" onmousedown="')
        self.search_url = 'https://google.com/search'
        self.agent = agent if agent is not None else 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Firefox/52.0'
        self.cookie = cookie if cookie is not None else ''

    def search(self, dork='site:example.com', start=0, num=100):
        try:
            req = urllib2.Request(
                '%s?%s' % (self.search_url, urllib.urlencode({
                    'q': dork,
                    'start': start,
                    'filter': 0,
                    'num': num
                })),
                None,
                {'User-Agent': self.agent, 'Cookie': self.cookie}
            )
            desc = urllib2.urlopen(req)
            html = desc.read()
            desc.close()
        except urllib2.URLError as err:
            print 'error:', err
            return None
        html_parser = HTMLParser()
        return [html_parser.unescape(link) for link in self.link_pattern.findall(html)]

class NameSearcher(object):
    def __init__(self, basename, dorker=None, levels=3):
        self.basename = basename
        self.dorker = dorker if dorker is not None else GoogleDork()
        self.levels = levels

    def gen_dork(self, names=[], level=1):
        pattern = re.compile(('[a-zA-Z0-9]+\\.' * level) + self.basename.replace('.','\\.'))
        names = [name for name in names if pattern.match(name) is not None]
        return "site:{}{} ".format('*.' * level, self.basename) + ' '.join(["-site:{}".format(name) for name in names])

    def search_names(self):
        names = []
        for level in xrange(1, self.levels + 1):
            keep = True
            while keep:
                keep = False
                dork = self.gen_dork(names, level)
                urls = self.dorker.search(dork)
                if urls is None:
                    return names
                for url in urls:
                    name = urlparse(url).hostname
                    if name is not None and name not in names:
                        print "[+] {}".format(name)
                        names.append(name)
                        keep = True
        return names


def main():
    parser = argparse.ArgumentParser(description='Search Subdomains.')
    parser.add_argument('domain', metavar='DOMAIN', type=str, help='The domain name. E.g.: example.com')
    parser.add_argument('-l', '--level', metavar='LEVEL', type=int, help='Max level. E.g.: 3', default=3)
    parser.add_argument('-c', '--cookie', metavar='COOKIE', type=str, help='Cookie string. E.g.: GOOGLE_ABUSE_EXEMPTION=ID=...')
    parser.add_argument('-a', '--agent', metavar='AGENT', type=str, help='User-Agent string. E.g.: Mozilla/5.0')
    args = parser.parse_args()

    dorker = GoogleDorker(cookie=args.cookie, agent=args.agent)
    searcher = NameSearcher(args.domain, dorker=dorker, levels=args.level)
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
