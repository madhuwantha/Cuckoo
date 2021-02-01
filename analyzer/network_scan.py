import re
import subprocess
import ipaddress
from Device import Device


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
        print(network)
        result = subprocess.run(['sudo', 'nmap', '-sP', str(network)], stdout=subprocess.PIPE)
        data = result.stdout.decode('utf-8')

        print(data)
        ip_adresses = re.findall( r'[0-9]+(?:\.[0-9]+){3}', data )

        mac_address = re.findall( r'(?:[0-9a-fA-F]:?){12}', data )

        net_data = []

        for i in range(len(mac_address)):
            device = Device(mac_address[i], ip_adresses[i], 'dev'+str(i))
            net_data.append(device)
        
        return net_data
 