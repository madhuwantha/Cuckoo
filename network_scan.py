import re
import subprocess
import ipaddress


class NetworkData(object):

    def get_host_ip(self):
        p1 = subprocess.Popen(['ip', 'addr'], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep', 'state UP', '-A2'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p3 = subprocess.Popen(['tail', '-n1'], stdin=p2.stdout, stdout=subprocess.PIPE)
        p4 = subprocess.Popen(['awk', '{print $2}'], stdin=p3.stdout, stdout=subprocess.PIPE)
        output = p4.communicate()[0]

        host_ip = output.decode('utf-8')[:-1]
        return host_ip
        

    def get_network_data(self):

        network = ipaddress.ip_network(self.get_host_ip(), strict=False)
        result = subprocess.run(['sudo', 'nmap', '-sP', str(network)], stdout=subprocess.PIPE)
        data = result.stdout.decode('utf-8')

        ip_adresses = re.findall( r'[0-9]+(?:\.[0-9]+){3}', data )
        mac_address = re.findall( r'(?:[0-9a-fA-F]:?){12}', data )

        return ip_adresses, mac_address
 