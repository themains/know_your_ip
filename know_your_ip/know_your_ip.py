#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import argparse
import logging
import requests
import time
import signal
from csv import DictWriter, DictReader
from configparser import RawConfigParser
from pkg_resources import resource_filename

import re
from bs4 import BeautifulSoup
from collections import defaultdict

import geoip2.webservice
import geoip2.database


from .ping import quiet_ping
from .traceroute import os_traceroute

from multiprocessing import Pool
from functools import partial

import shodan

logging.getLogger("requests").setLevel(logging.WARNING)

LOG_FILE = 'know_your_ip.log'
CFG_FILE = resource_filename(__name__, "know_your_ip.cfg")

MAX_RETRIES = 5


def setup_logger():
    """ Set up logging"""
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filename=LOG_FILE,
                        filemode='w')
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)


def table_to_list(table):
    dct = table_to_2d_dict(table)
    return list(iter_2d_dict(dct))


def table_to_2d_dict(table):
    result = defaultdict(lambda: defaultdict())
    for row_i, row in enumerate(table.find_all('tr')):
        for col_i, col in enumerate(row.find_all(['td', 'th'])):
            colspan = int(col.get('colspan', 1))
            rowspan = int(col.get('rowspan', 1))
            col_data = col.text
            while row_i in result and col_i in result[row_i]:
                col_i += 1
            for i in range(row_i, row_i + rowspan):
                for j in range(col_i, col_i + colspan):
                    result[i][j] = col_data
    return result


def iter_2d_dict(dct):
    for i, row in sorted(dct.items()):
        cols = []
        for j, col in sorted(row.items()):
            cols.append(col)
        yield cols


def flatten_dict(dd, separator='_', prefix=''):
    return {prefix + separator + k if prefix else k: v
            for kk, vv in dd.items()
            for k, v in flatten_dict(vv, separator, kk).items()
            } if isinstance(dd, dict) else {prefix: dd}


def clean_colname(name):
    c = re.sub('\W|^(?=\d)', '_', name)
    return (re.sub('_+', '_', c)).lower()


def load_config(args=None):
    """Load details of API keys etc. from the config. file

    Args:
        args: load default config from ``<package dir>/know_your_ip.cfg`` if None or
            load config from the given filename.

    Returns:
        obj: configuration object.

    Notes:
        See :download:`this default know_your_ip.cfg <../../know_your_ip/know_your_ip.cfg>`
    """

    if args is None or isinstance(args, str):
        namespace = argparse.Namespace()
        if args is None:
            namespace.config = CFG_FILE
        else:
            namespace.config = args
        args = namespace
    config = RawConfigParser()
    config.read(args.config)

    # Maxmind configuration
    args.maxmind_dbpath = config.get('maxmind', 'dbpath')
    if not os.path.exists(args.maxmind_dbpath):
        args.maxmind_dbpath = resource_filename(__name__, 'db')
    args.maxmind_enable = config.getint('maxmind', 'enable')

    # GeoNames.org configuration
    args.geonames_username = config.get('geonames', 'username')
    args.geonames_enable = config.getint('geonames', 'enable')

    # tzwhere configuration
    args.tzwhere_enable = config.getint('tzwhere', 'enable')

    # abuseipdb configuration
    args.abuseipdb_enable = config.getint('abuseipdb', 'enable')
    args.abuseipdb_key = config.get('abuseipdb', 'key')
    args.abuseipdb_days = config.getint('abuseipdb', 'days')
    cat_file = config.get('abuseipdb', 'cat_catid')
    if not os.path.exists(cat_file):
        cat_file = resource_filename(__name__, 'abuseipdb_cat_catid.csv')
    cat = {}
    with open(cat_file, 'rt') as f:
        reader = DictReader(f)
        for r in reader:
            cat[r['catid']] = r['category']
    args.abuseipdb_category = cat

    # ping configuration
    args.ping_enable = config.getint('ping', 'enable')
    args.ping_timeout = config.getint('ping', 'timeout')
    args.ping_count = config.getint('ping', 'count')

    # traceroute configuration
    args.traceroute_enable = config.getint('traceroute', 'enable')
    args.traceroute_max_hops = config.getint('traceroute', 'max_hops')

    # ipvoid configuration
    args.ipvoid_enable = config.getint('ipvoid', 'enable')

    # Censys configuration
    args.censys_enable = config.getint('censys', 'enable')
    args.censys_api_url = config.get('censys', 'api_url')
    args.censys_uid = config.get('censys', 'uid')
    args.censys_secret = config.get('censys', 'secret')

    # shodan.io configuration
    args.shodan_enable = config.getint('shodan', 'enable')
    args.shodan_api_key = config.get('shodan', 'api_key')

    # virustotal configuration
    args.virustotal_enable = config.getint('virustotal', 'enable')
    args.virustotal_api_key = config.get('virustotal', 'api_key')

    # Output columns configuration
    columns_file = config.get('output', 'columns')
    if not os.path.exists(columns_file):
        columns_file = resource_filename(__name__, 'columns.txt')
    lines = []
    try:
        with open(columns_file, 'rt') as f:
            lines = [a.strip() for a in f.read().split('\n')]
    except Exception as e:
        logging.error(e)
    columns = []
    for l in lines:
        if len(l) and not l.startswith('#'):
            columns.append(l)
    args.output_columns = columns

    return args


def maxmind_geocode_ip(args, ip):
    """Get location of IP address from Maxmind City database (GeoLite2-City.mmdb)

    Args:
        args: via the ``load_config`` function.
        ip: an IP address

    Returns:
        dict: Geolocation data

    Notes:
        There are other Maxmind databases including:
            * Country Database (GeoLite2-Country.mmdb)
            * Anonymous IP Database (GeoIP2-Anonymouse-IP.mmdb)
            * Connection-Type Database (GeoIP2-Connection-Type.mmdb)
            * Domain Database (GeoIP2-Domain.mmdb)
            * ISP Database (GeoIP2-ISP.mmdb)
    """

    reader = geoip2.database.Reader(os.path.join(args.maxmind_dbpath,
                                    'GeoLite2-City.mmdb'))
    response = reader.city(ip)
    out = flatten_dict(response.raw, separator='.')
    reader.close()
    result = {}
    for k in out.keys():
        result['maxmind.{0}'.format(k)] = out[k]
    return result


def geonames_timezone(args, lat, lng):
    """Get timezone for a latitude/longitude from GeoNames

    Args:
        args: via the ``load_config`` function.
        lat (float): latitude
        lng (float): longitude

    Returns:
        dict: GeoNames data

    Notes:
        Please visit `this link <http://www.geonames.org/export/ws-overview.html>`_
        for more information about GeoNames.org Web Services

        e.g. URL: http://api.geonames.org/timezone?lat=47.01&lng=10.2&username=demo

        Limit:
            30,000 credits daily limit per application
            (identified by the parameter 'username'), the hourly limit is
            2000 credits. A credit is a web service request hit for most services.
            An exception is thrown when the limit is exceeded.

    Example:
        geonames_timezone(args, 32.0617, 118.7778)
    """

    data = {}
    payload = {'lat': lat, 'lng': lng, 'username': args.geonames_username}
    retry = 0
    while retry < MAX_RETRIES:
        try:
            r = requests.get('http://api.geonames.org/timezoneJSON',
                             params=payload)
            if r.status_code == 200:
                out = r.json()
                for k in out.keys():
                    data['geonames.{0}'.format(k)] = out[k]
                break
        except Exception as e:
            logging.warn('geonames_timezone: ' + str(e))
            retry += 1
            time.sleep(retry)
    return data


def tzwhere_timezone(args, lat, lng):
    """Get timezone of a latitude/longitude using the tzwhere package.

    Args:
        args: via the ``load_config`` function.
        lat (float): latitude
        lng (float): longitude

    Returns:
        dict: timezone data

    Example:
        tzwhere_timezone(args, 32.0617, 118.7778)
    """

    from tzwhere import tzwhere

    if not hasattr(args, 'tzwhere_tz'):
        args.tzwhere_tz = tzwhere.tzwhere()
    return args.tzwhere_tz.tzNameAt(lat, lng)


def abuseipdb_api(args, ip):
    """Get information from AbuseIPDB via `API <https://www.abuseipdb.com/api.html>`_

    Args:
        args: via the ``load_config`` function.
        ip (str): an IP address
    
    Returns:
        dict: AbuseIPDB information

    References:
        * https://www.abuseipdb.com/api.html
        * e.g. https://www.abuseipdb.com/check/[IP]/json?key=[API_KEY]&days=[DAYS]

    Example:
        abuseipdb_api(args, '222.186.30.49')
    """

    out = {}
    retry = 0
    while retry < MAX_RETRIES:
        try:
            r = requests.get('https://www.abuseipdb.com/check/{ip:s}/json?key={key:s}&days={days:d}'
                             .format(ip=ip, key=args.abuseipdb_key, days=args.abuseipdb_days))
            if r.status_code == 200:
                js = r.json()
                if isinstance(js, list):
                    if len(js) == 0:
                        break
                    js = js[0]
                out = dict()
                for k in js.keys():
                    if k == 'category':
                        c = []
                        for a in js[k]:
                            a = str(a)
                            if a in args.abuseipdb_category:
                                c.append(args.abuseipdb_category[a])
                        out['abuseipdb.{0}'.format(k)] = '|'.join(c)
                    else:
                        out['abuseipdb.{0}'.format(k)] = js[k]
                break
        except Exception as e:
            logging.warn('abuseipdb_api: ' + str(e))
            retry += 1
            time.sleep(retry)
    return out


def abuseipdb_web(args, ip):
    """Get information from `AbuseIPDB website <https://www.abuseipdb.com/>`_

    Args:
        args: via the ``load_config`` function.
        ip (str): an IP address
    
    Returns:
        dict: AbuseIPDB information

    References:
        e.g. http://www.abuseipdb.com/check/94.31.29.154

    Example:
        abuseipdb_web(args, '222.186.30.49')
    """

    data = {}
    retry = 0
    while retry < MAX_RETRIES:
        try:
            r = requests.get('http://www.abuseipdb.com/check/' + ip)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'lxml')
                for t in soup.select('table'):
                    table = table_to_list(t)
                    for r in table:
                        col = r[0].strip()
                        col = clean_colname(col)
                        data['abuseipdb.' + col] = r[1]
                    break
                div = soup.select('div#body div.well')[0]
                result = div.text
                if result.find('was not found') != -1:
                    data['abuseipdb.found'] = 0
                else:
                    data['abuseipdb.found'] = 1
                count = 0
                for m in re.finditer(r'was reported (\d+) time', result):
                    count = int(m.group(1))
                    break
                if count:
                    for t in soup.select('table')[1:]:
                        table = table_to_list(t)
                        rows = []
                        for r in table:
                            rows.append('|'.join(r))
                        break
                    data['abuseipdb.history'] = '\n'.join(rows)
                break
        except Exception as e:
            logging.warn('abuseipdb_web: ' + str(e))
            retry += 1
            time.sleep(retry)
    return data


def ipvoid_scan(args, ip):
    """Get Blacklist information from `IPVoid website <http://www.ipvoid.com/ip-blacklist-check>`_

    Args:
        args: via the ``load_config`` function.
        ip (str): an IP address
    
    Returns:
        dict: IPVoid information

    Example:
        ipvoid_scan(args, '222.186.30.49')
    """

    retry = 0
    while retry < MAX_RETRIES:
        try:
            data = {}
            r = requests.post('http://www.ipvoid.com/ip-blacklist-check/', data={'ip': ip})
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'lxml')
                data = {}
                tables = soup.select('table')
                table = table_to_list(tables[0])
                for r in table:
                    col = 'ipvoid.' + clean_colname(r[0])
                    data[col] = r[1]
                alerts = []
                for tr in tables[1].select('tr'):
                    tds = tr.select('td')
                    if len(tds) == 2:
                        if len(tds[0].select('i.text-danger')):
                            alerts.append(tds[0].text.strip())
                data['ipvoid.alerts'] = '|'.join(alerts)
                break
        except Exception as e:
            logging.warn('ipvoid_scan: ' + str(e))
            retry += 1
            time.sleep(retry)
    return data


def censys_api(args, ip):
    """Get information from Censys `Search API <https://censys.io/api/v1/docs/search>`_

    Args:
        args: via the ``load_config`` function.
        ip (str): an IP address
    Returns:
        dict: Censys information

    References:
        Fields: https://censys.io/ipv4/help

    Example:
        censys_api(args, '222.186.30.49')
    """

    fields = []
    for c in args.output_columns:
        if c.startswith('censys.'):
            fields.append(c.replace('censys.', ''))

    payload = {"query": "ip:" + ip,
               "page": 1,
               "fields": fields,
               }

    data = {}
    retry = 0
    while retry < MAX_RETRIES:
        try:
            r = requests.post(args.censys_api_url + "/search/ipv4",
                              auth=(args.censys_uid, args.censys_secret),
                              json=payload)
            if r.status_code == 200:
                out = r.json()
                if 'results' in out and len(out['results']):
                    out = out['results'][0]
                for k in out.keys():
                    if isinstance(out[k], list):
                        out[k] = '|'.join([str(i) for i in out[k]])
                    data['censys.' + k] = out[k]
                break
        except Exception as e:
            logging.warn('censys_api: ' + str(e))
            retry += 1
            time.sleep(retry)
    return data


def shodan_api(args, ip):
    """Get information from Shodan

    Args:
        args: via the ``load_config`` function.
        ip (str): an IP address
    
    Returns:
        dict: Shodan information

    Example:
        shodan_api(args, '222.186.30.49')
    """

    api = shodan.Shodan(args.shodan_api_key)
    data = {}
    try:
        out = api.host(ip)
        out = flatten_dict(out)
        for k in out.keys():
            if isinstance(out[k], list):
                out[k] = '|'.join([str(i) for i in out[k]])
            data['shodan.' + k] = out[k]
    except shodan.APIError as e:
        logging.warn('shodan_api(ip={0:s}): {1!s}'.format(ip, e))
    return data


def virustotal_api(args, ip):
    """Get information from VirusTotal `Public API <https://www.virustotal.com/th/documentation/public-api/>`_

    Args:
        args: via the ``load_config`` function.
        ip (str): an IP address
    
    Returns:
        dict: Virustotal information

    Notes:
        Public API Limitation
            * Privileges  public key
            * Request rate    4 requests/minute
            * Daily quota 5760 requests/day
            * Monthly quota   178560 requests/month

    Example:
        virustotal_api(args, '222.186.30.49')
    """

    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'ip': ip, 'apikey': args.virustotal_api_key}
    retry = 0
    data = {}
    while retry < MAX_RETRIES:
        try:
            r = requests.get(url, params=params)
            if r.status_code == 200:
                out = r.json()
                out = flatten_dict(out)
                for k in out.keys():
                    if isinstance(out[k], list):
                        out[k] = '|'.join([str(i) for i in out[k]])
                    data['virustotal.' + k] = out[k]
                break
        except Exception as e:
            logging.warn('virustotal_api: ' + str(e))
            retry += 1
            time.sleep(retry)
    return data


def ping(args, ip):
    """Get information using Ping (ICMP protocol)

    Args:
        args: via the ``load_config`` function.
        ip (str): an IP address
    
    Returns:
        dict: Ping statistics information

    Notes:
        Ping function is based on a pure python ping implementation using
        raw socket and you must have root (on Linux) or Admin (on Windows)
        privileges to run.

    Example:
        ping(args, '222.186.30.49')
    """

    data = {}
    data['ping.count'] = args.ping_count
    data['ping.timeout'] = args.ping_timeout
    stat = quiet_ping(ip, timeout=args.ping_timeout, count=args.ping_count)
    if stat:
        data['ping.max'] = stat[0]
        data['ping.min'] = stat[1]
        data['ping.avg'] = stat[2]
        data['ping.percent_loss'] = stat[3] * 100
    return data


def traceroute(args, ip):
    """Get information using traceroute

    Args:
        args: via the ``load_config`` function.
        ip (str): an IP address
    
    Returns:
        dict: traceroute information

    Notes:
        Currently traceroute uses the operating system command traceroute on
        Linux and tracert on Windows.

    Example:
        traceroute(args, '222.186.30.49')
    """

    data = {}
    hops = os_traceroute(ip, max_hops=args.traceroute_max_hops)
    data['traceroute.max_hops'] = args.traceroute_max_hops
    data['traceroute.hops'] = hops
    return data


def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def query_ip(args, ip):
    """Get all information of IP address

    Args:
        args: via the ``load_config`` function.
        ip (str): an IP address
    
    Returns:
        dict: Information on the given IP address

    Example:
        query_ip(args, '222.186.30.49')
    """

    data = {'ip': ip}
    udata = {}
    try:
        if args.ping_enable:
            out = ping(args, ip)
            data.update(out)
        if args.traceroute_enable:
            out = traceroute(args, ip)
            data.update(out)
        if args.maxmind_enable:
            out = maxmind_geocode_ip(args, ip)
            lat = out['maxmind.location.latitude']
            lng = out['maxmind.location.longitude']
            data.update(out)
        if args.geonames_enable:
            out = geonames_timezone(args, lat, lng)
            data.update(out)
        if args.tzwhere_enable:
            tz = tzwhere_timezone(args, lat, lng)
            data['tzwhere.timezone'] = tz
        if args.abuseipdb_enable:
            out = abuseipdb_api(args, ip)
            data.update(out)
            out = abuseipdb_web(args, ip)
            data.update(out)
        if args.ipvoid_enable:
            out = ipvoid_scan(args, ip)
            data.update(out)
        if args.censys_enable:
            out = censys_api(args, ip)
            data.update(out)
        if args.shodan_enable:
            out = shodan_api(args, ip)
            data.update(out)
        if args.virustotal_enable:
            out = virustotal_api(args, ip)
            data.update(out)
        # FIXME: Encode all columns to 'utf-8'
        for k, v in data.items():
            if k in args.output_columns:
                try:
                    udata[k] = v.encode('utf-8')
                except:
                    udata[k] = v
    except Exception as e:
        logging.error(e)
        if args.verbose:
            import traceback
            traceback.print_exc()
    return udata


def main():
    setup_logger()

    parser = argparse.ArgumentParser(description='Know Your IP')
    parser.add_argument('ip', nargs='*', help='IP Address(es)')
    parser.add_argument('-f', '--file', help='List of IP addresses file')
    parser.add_argument('-c', '--config', default=CFG_FILE,
                        help='Configuration file')
    parser.add_argument('-o', '--output', default='output.csv',
                        help='Output CSV file name')
    parser.add_argument('-n', '--max-conn', type=int, default=5,
                        help='Max concurrent connections')
    parser.add_argument('--from', default=0, type=int, dest='from_row',
                        help='From row number')
    parser.add_argument('--to', default=0, type=int,
                        help='To row number')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='Verbose mode')
    parser.add_argument('--no-header', dest='header', action='store_false',
                        help='Output without header at the first row')
    parser.set_defaults(header=True)
    parser.set_defaults(verbose=False)

    args = parser.parse_args()

    if args.file is None and len(args.ip) == 0:
        parser.error("at least one of IP address and --file is required")

    args = load_config(args)

    pool = Pool(processes=args.max_conn, initializer=init_worker)

    if args.file:
        with open(args.file) as f:
            args.ip = [a.strip() for a in f.read().split('\n')
                       if ((a.strip() != '') and not a.startswith('#'))]

    f = open(args.output, 'wt')
    writer = DictWriter(f, fieldnames=args.output_columns)
    if args.header:
        writer.writeheader()
    row = 0
    while row < len(args.ip):
        if row < args.from_row:
            row += 1
            continue
        if args.to != 0 and row >= args.to:
            logging.info("Stop at row {0}".format(row))
            break
        logging.info("Row: {0}".format(row))
        try:
            partial_query_ip = partial(query_ip, args)
            ips = args.ip[row:row + args.max_conn]
            results = pool.map(partial_query_ip, ips)
            for data in results:
                edata = {}
                for k, v in data.items():
                    if v is not None:
                        try:
                            edata[k] = v.decode('utf-8')
                        except:
                            edata[k] = v
                writer.writerow(edata)
                row += 1
        except KeyboardInterrupt:
            pool.terminate()
            pool.join()
            break
        except Exception as e:
            logging.error(e)
            if args.verbose:
                import traceback
                traceback.print_exc()
    f.close()


if __name__ == "__main__":
    sys.exit(main())
