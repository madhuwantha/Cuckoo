from HashTab import HashTab
from Shell import Shell
import csv
from network_scan import NetworkData
import ipaddress
from os import path
import subprocess
import time



def test():
    size = 1000
    missing = 0
    found = 0

    # create a hash table with an initially small number of bukets
    c = HashTab(100)

    # Now insert size key/data pairs, where the key is a string consisting
    # of the concatenation of "foobarbaz" and i, and the data is i
    inserted = 0
    for i in range(size):
        if c.insert(str(i) + "foobarbaz", i):
            inserted += 1
    print("There were", inserted, "nodes successfully inserted")

    # Make sure that all key data pairs that we inserted can be found in the
    # hash table. This ensures that resizing the number of buckets didn't
    # cause some key/data pairs to be lost.
    for i in range(size):
        ans = c.find(str(i) + "foobarbaz")
        if ans is None or ans != i:
            print(i, "Couldn't find key", str(i) + "foobarbaz")
            missing += 1

    print("There were", missing, "records missing from Cuckoo")

    # Makes sure that all key data pairs were successfully deleted
    for i in range(size):
        c.delete(str(i) + "foobarbaz")

    for i in range(size):
        ans = c.find(str(i) + "foobarbaz")
        if ans != None or ans == i:
            print(i, "Couldn't delete key", str(i) + "foobarbaz")
            found += 1
    print("There were", found, "records not deleted from Cuckoo")


def packet_anlyze():
    network_data  = NetworkData()   
    ip_adresses, mac_addresses = network_data.get_network_data()

    print(ip_adresses)
    print(mac_addresses)
    
    if(not(path.exists('allowed.csv'))):
        subprocess.run(['touch','allowed.csv'], stdout=subprocess.PIPE)

    allowed_macs = []
    allowed_destinations = []

    new_macs = []
    new_destinations = []
    
    try:
        csv_file = open('allowed.csv', mode='r')
        csv_reader = csv.DictReader(csv_file, fieldnames=['mac', 'dst_ip'])
            
        for row in csv_reader:
            allowed_macs.append(row['mac'])
            allowed_destinations.append(row['dst_ip'])
            #print(row['src_ip'] + " " + row['src_port'] + " " + row['dst_ip'] + " " + row['dst_port'])
            #line_count += 1

        csv_file.close()

        csv_file = open('allowed.csv', mode='a')
        csv_writer = csv.writer(csv_file, delimiter=',', lineterminator='\n')

        size = 1000
        missing = 0
        found = 0
        inserted = 0
        c = HashTab(100)
        ip_routes = []

        for index, mac in enumerate(mac_addresses):
            
            if mac[1] not in allowed_macs:
                new_dest = input("Please enter the allowed destination ip for device "+str(mac[1])+" : ")
                allowed_macs.append(mac)
                allowed_destinations.append(new_dest)
                new_macs.append(mac)
                new_destinations.append(new_dest)
            
            ip_route_forward = ip_adresses[index] + " " + allowed_destinations[allowed_macs.index(mac[1])]
            ip_route_backward = allowed_destinations[allowed_macs.index(mac[1])] + " " + ip_adresses[index]  
            ip_routes.append(ip_route_forward)
            ip_routes.append(ip_route_backward)

            if c.insert(ip_route_forward, index):
                inserted += 1
            
            if c.insert(ip_route_backward, index):
                inserted += 1
                
            print("There were", inserted, "allowed routes successfully inserted")



        

        for index, mac in enumerate(new_macs):
            #ip_route = mac[1] + " " + new_destinations[index]
            #print(ip_route)
            csv_writer.writerow([mac[1] , new_destinations[index]])
        
        csv_file.close()


        pcap_path = input("Please enter relative file path to pcap : ")
        
        shell = Shell()
        shell.execute("echo \"1996\" |  sudo -S tshark -r " + str(pcap_path) + " -T fields -E separator=, -E quote=d -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e _ws.col.SourcePort -e _ws.col.Destination -e _ws.col.DestinationPort -e _ws.col.Protocol -e _ws.col.Length -e _ws.col.Info > data.csv")

        csv_file = open('data.csv', mode='r')
        csv_reader = csv.DictReader(csv_file, fieldnames=['number', 'time', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'proto', 'length', 'info'])

        anomalies = []

        for row in csv_reader:
            route = row['src_ip'] + " " + row['dst_ip']
            route_obtained = c.find(route)
            
            if route_obtained == None or route_obtained != route:
                anomalies.append(row)
                found += 1

        csv_file.close()

        print(anomalies)

        




    except IOError:
        print("I/O error")

def __main():

    shell = Shell()
    while(True):
        shell.execute("echo 123")
        time.sleep(1)
        shell.execute("echo 1234")
        time.sleep(5)

if __name__ == '__main__':
    __main()
