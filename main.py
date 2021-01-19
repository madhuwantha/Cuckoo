from HashTab import HashTab
from Shell import Shell
import csv
from network_scan import NetworkData
import ipaddress
from os import path
import subprocess
import time
import sys
import threading
import os
import pandas as pd
import queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import OnMyWatch
import pyshark

q = queue.Queue()

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

def collecting_traffic(name):
    print(str(name)+ ' Thread starts')
    shell = Shell()
    net_data = NetworkData()

    ip = net_data.get_host_ip()
    net = ipaddress.ip_network(ip, strict=False)
    shell.execute("echo \"1996\" | sudo -S tcpdump -i any -v -G 60 net " + str(net) + " -w data-%S.pcap")

def create_profiles(name):
    print(str(name)+ ' Thread starts')
    if(not(path.exists('devices.csv'))):
        network_data = NetworkData()
        current_devices = network_data.get_network_data()
        devices_dict = {
            'name' : [],
            'mac' : [],
            'internal_ip' : []
        }

        for i in range(len(current_devices)):
            if(not(path.exists(current_devices[i].name))):
                open(current_devices[i].name+'.csv', 'a').close()

            devices_dict['name'].append(current_devices[i].name)
            devices_dict['mac'].append(current_devices[i].mac)
            devices_dict['internal_ip'].append(current_devices[i].ip)

    
        
        df = pd.DataFrame(devices_dict)
        df.to_csv('devices.csv', index=False)

def __main():

    thread1 = threading.Thread(target=collecting_traffic,args=('t1', ))
    thread1.start()
    thread2 = threading.Thread(target=create_profiles,args=('t2', ))
    thread2.start()

    dfQueue = queue.Queue()

    watch = OnMyWatch.OnMyWatch()
    watch.run(dfQueue)

    c = HashTab(100)
    i = 0
    while( True ):
        if(dfQueue.qsize() > 0):
            if(path.exists('devices.csv')):
                traffic_frame = dfQueue.get()
                devices_frame = pd.read_csv('devices.csv')

                for index,row in devices_frame.iterrows():
                    try:
                        routes_frame = traffic_frame.loc[(traffic_frame.src_ip == row[2]) & (traffic_frame.protocol != 'ARP')]
                        profile_frame = routes_frame.groupby(['dst_ip', 'dst_port', 'protocol']).length.agg(['count', 'mean'])

                        #for index1,row1 in profile_frame.iterrows():
                            #route_forward = str(row[2]) + str(row1['dst_ip']) + str(row1['dst_port']) + 'OUT'
                        
                        profile_file = row['name']+".csv"
                        profile_frame.to_csv(profile_file)
                    except:
                        print(row[2])

            break
        
        else:
            i = i + 1 
            print(i)
    
    print("Profiling complete")
        

    
    #thread3 = threading.Thread(target=read_traffic,args=('t3', ))
    #thread3.start()
    #if(q.qsize() > 0 ):
    #    print(q.get())
    #path = os.path.abspath('data1.pcap')
    #cap = pyshark.FileCapture('data1.pcap')
    #print(cap[10])
     


    #thread2 = threading.Thread(target=read_traffic,args=('t2', ))
    #thread2.start() 
    #shell = Shell()
    #os.rename(file, 'data1.pcap')
    #output = file[:-5] + '.csv'
    #file = 'data-18.pcap'
    #shell.execute("echo \"1996\" |  sudo -S tshark -r " + file +" -T fields -E separator=, -E quote=d -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e _ws.col.SourcePort -e _ws.col.Destination -e _ws.col.DestinationPort -e _ws.col.Protocol -e _ws.col.Length -e _ws.col.Info > traffic.csv")



if __name__ == '__main__':
    __main()
