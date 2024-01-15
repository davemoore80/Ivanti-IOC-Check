import sys
import re
import csv
import requests
from socket import gethostbyname_ex
from pprint import pprint
import ipaddress

class IvantiIOC:

    def __init__(self):

        self.address_data_list = []
        self.address_data = {}
        self.filelines = []
        self.fileaddresses = []

        self.urls = {
            'Digital Ocean': 'https://digitalocean.com/geo/google.csv',
            'Linode': 'https://geoip.linode.com/',
            'Volexity': 'https://raw.githubusercontent.com/volexity/threat-intel/main/2024/2024-01-10%20Ivanti%20Connect%20Secure/indicators/iocs.csv',
            'Vultr': 'https://geofeed.constant.com/'
        }

    def getCSVData(self, url):

        url = url

        download = requests.get(url)
        decoded_content = download.content.decode('utf-8')

        cr = csv.reader(decoded_content.splitlines(), delimiter=',')
        ioclist = list(cr)
        
        return ioclist

    def getGeoCSV(self, source):

        url = self.urls[source]

        response = self.getCSVData(url)

        for row in response:

            if re.match(r'^( )*#', row[0]):
                pass
            else:
                try:
                    convert_network = (
                        int(ipaddress.IPv4Network(row[0]).network_address),
                        int(ipaddress.IPv4Network(row[0]).broadcast_address),
                        row[0]
                    )

                    self.address_data_list.append(convert_network)
                    self.address_data[row[0]] = {
                        'source': source,
                        'type': 'network',
                        'country': row[1],
                        'city': row[3],
                        'postcode': row[4]
                    }

                except ipaddress.AddressValueError:
                    pass



    def getVolexity(self):

        url = self.urls['Volexity']

        response = self.getCSVData(url)

        for row in response:

            if re.match(r'^( )*#', row[0]):
                pass
            
            elif re.match(r'.*\.(com|net|co.uk|org)$', row[0]):
                resolved_addresses = gethostbyname_ex(row[0])[2]
                for ip in resolved_addresses:
                     self.addSingleIP(ip, '***************** Volexity IOC *****************')

            else:
                try:
                    if ipaddress.IPv4Address(row[0]):
                        row[0] = row[0] + '/32'
                except ipaddress.AddressValueError:
                    pass

                try:
                    convert_network = (
                        int(ipaddress.IPv4Network(row[0]).network_address),
                        int(ipaddress.IPv4Network(row[0]).broadcast_address),
                        row[0]
                    )

                    self.address_data_list.append(convert_network)
                    self.address_data[row[0]] = {
                        'source': '***************** Volexity IOC *****************',
                        'type': row[1],
                        'country': 'Unknown',
                        'city': 'Unknown',
                        'postcode': 'Unknown',
                    }

                except ipaddress.AddressValueError:
                    pass

    
    def addSingleIP(self, ip, source=''):

        try:
            if ipaddress.IPv4Address(ip):
                ip = ip + '/32'

            convert_network = (
                int(ipaddress.IPv4Network(ip).network_address),
                int(ipaddress.IPv4Network(ip).broadcast_address),
                ip
            ) 

            self.address_data_list.append(convert_network)
            self.address_data[ip] = {
                'source': source,
                'type': 'ipaddress',
                'country': 'Unknown',
                'city': 'Unknown',
                'postcode': 'Unknown',
            }

        except ipaddress.AddressValueError:
            pass

   

    def getAll(self):

        self.getGeoCSV('Digital Ocean')
        self.getGeoCSV('Linode')
        self.getGeoCSV('Vultr')
        self.getVolexity()

        return self.address_data_list, self.address_data
    
    def readFile(self, filename):

        try:
            with open(filename, 'r') as f:
                self.filedata = f.readlines()
        except FileNotFoundError:
            print('File not found')
            quit()

        return self.filedata

    def extractFromFile(self):

        if len(self.filedata) == 0:
            print('File appears to be empty')
            quit()
        else:
            for line in self.filedata:
                matchaddr = re.findall(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', line)

                if len(matchaddr) == 0:
                    pass
                else:
                    for addr in matchaddr:
                        if addr not in self.fileaddresses:
                            self.fileaddresses.append(addr.strip())

        return self.fileaddresses

    def crossCheck(self):

        for a in self.fileaddresses:
            for data_addr in self.address_data_list:
                try:

                    if (int(ipaddress.IPv4Address(a)) >= data_addr[0]) and (int(ipaddress.IPv4Address(a)) <= data_addr[1]):
                        print(f'Found {a} in {data_addr[2]}')
                        print(f'    This is related to {self.address_data[data_addr[2]]["source"]}')
                except ipaddress.AddressValueError:
                    pass


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print('You have not provided a file to parse')
        quit()
    elif len(sys.argv) > 2:
        print('Too many arguments provided, just include a single filename')
        quit()
    else:
        filename = sys.argv[1]

    ioc = IvantiIOC()
        
    lines = ioc.readFile(filename)
    addresses = ioc.extractFromFile()

    ioc.getAll()
    ioc.crossCheck()


    