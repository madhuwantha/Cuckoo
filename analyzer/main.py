from HashTab import HashTab
from Shell import Shell
import csv
from network_scan import NetworkData
import subprocess
import threading
import os
import pandas as pd
import queue
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from multiprocessing import Process, Pool

q = queue.Queue()
c = HashTab(100)
has_profiles = False
times = 0
writeHeader = True

class Handler(FileSystemEventHandler):

    def __init__(self, file_queue):
        self.file_queue = file_queue
        self.shell = Shell() 
   
    def on_any_event(self, event):
        if event.is_directory: 
            return None
  
        elif event.event_type == 'created': 
            # Event is created, you can process it now 
            print("Watchdog received created event - % s." % event.src_path)

            if('traffic' in str(event.src_path)):
                self.file_queue.put(str(event.src_path)[2:])
                print(self.file_queue.qsize())

def profile(filename):
    global has_profiles
    global times   
    i = 0
    inserted = 0
    
    while( True ):
        profiled = False
        traffic_frame = pd.DataFrame(read_traffic(filename))

        if(os.path.exists('devices.csv') and not(traffic_frame.empty)):
            devices_frame = pd.read_csv('devices.csv')
                
            for index,row in devices_frame.iterrows():
                routes_frame = traffic_frame.loc[(traffic_frame.src_ip == row[2]) | (traffic_frame.dst_ip == row[2])]
                if(not(routes_frame.empty)):
                    routes_frame['dir'] = routes_frame.apply(lambda x: direction(str(row[2]),x['src_ip'], x['dst_ip']), axis=1)
                    profile_frame = routes_frame.groupby(['src_ip','dst_ip', 'dst_port', 'protocol', 'dir'], as_index=False).length.agg(['count', 'mean']).reset_index()

                    for index1,row1 in profile_frame.iterrows():
                        route = str(row1['src_ip']) + str(row1['dst_ip']) + str(row1['dst_port']) + str(row1['dir'])
                        if c.insert(route, index1):
                            inserted +=1
                            
                    profile_file = row['name']+".csv"
                    profile_frame = profile_frame.drop('src_ip', axis=1)
                    profile_frame.to_csv(profile_file, index=False, mode='a')
            profiled = True
            times = times + 1
            if (times > 2):
                has_profiles = True
            print('inserted' + str(inserted) )
            #print("Exception")
        else:
            i = i + 1 
            print(i)

        if(profiled):
            break
    
    print("Profiling complete")


def filter_anomalies(filename):
    found = 0
    missing = 0
    anomalies = []
    allowes = []
    i = 0
    global writeHeader
   
    traffic_frame2 = pd.DataFrame(read_traffic(filename))

    if(os.path.exists('devices.csv') and not(traffic_frame2.empty)):
        devices_frame2 = pd.read_csv('devices.csv')   
                
        for index,row in traffic_frame2.iterrows():
            direc = ''
            if(row['src_ip'] in devices_frame2.internal_ip.values):
                direc = 'OUT'
            elif(row['dst_ip'] in devices_frame2.internal_ip.values):
                direc = 'IN'
                    
            route = str(row['src_ip']) + str(row['dst_ip']) + str(row['dst_port']) + str(direc)
            index = c.find(route)
            if index is None:
                print(index, "Couldn't find key", route)
                missing += 1
                anomalies.append(row)
            else:
                print(index, "Found", route)
                found += 1
                allowes.append(row)
                    
        print(found)
            #print("Exception")

    else:
        i = i + 1 
        print(i)
    
    anomaly_df = pd.DataFrame(anomalies)
    allowes_df = pd.DataFrame(allowes)
    
    if (writeHeader):
        anomaly_df.to_csv('anomalies.csv', index=False, mode='a',  header=True)
        allowes_df.to_csv('allowes.csv', index=False, mode='a',  header=True)
    else:
        anomaly_df.to_csv('anomalies.csv', index=False, mode='a',  header=False)
        allowes_df.to_csv('allowes.csv', index=False, mode='a',  header=False)


def create_profiles(name):
    print(str(name)+ ' Thread starts')
    if(not(os.path.exists('devices.csv'))):
        network_data = NetworkData()
        current_devices = network_data.get_network_data()
        print(current_devices)
        devices_dict = {
            'name' : [],
            'mac' : [],
            'internal_ip' : []
        }

        for i in range(len(current_devices)):
            if(not(os.path.exists(current_devices[i].name))):
                open(current_devices[i].name+'.csv', 'a').close()

            devices_dict['name'].append(current_devices[i].name)
            devices_dict['mac'].append(current_devices[i].mac)
            devices_dict['internal_ip'].append(current_devices[i].ip)

    
        
        df = pd.DataFrame(devices_dict)
        df.to_csv('devices.csv', index=False)


def direction(device_ip, src_ip, dst_ip):
    if(device_ip == src_ip):
        return 'OUT'
    elif(device_ip == dst_ip):
        return 'IN'
    else:
        return 'NA'

def read_traffic(filename):
    if (os.path.exists(filename)):
        packets = []
        filepath = filename
        csv_file = open(filepath, mode='r')
        csv_reader = csv.DictReader(csv_file, fieldnames=['no','time', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'length', 'info'])
            
        for row in csv_reader:
            if( row['time'] != '' and row['time'] != None and row['src_ip'].split('.')[3] != str(2) and row['dst_ip'].split('.')[3] != str(2) ):
                packet = {
                'time' :  row['time'],
                'src_ip' : {True : row['src_ip'], False: '0.0.0.0' } [row['src_ip'] != ''],
                'src_port' : {True : row['src_port'], False: '0' } [row['src_port'] != ''],
                'dst_ip' : {True : row['dst_ip'], False: '0.0.0.0' } [row['dst_ip'] != ''],
                'dst_port' : {True : row['dst_port'], False: '0' } [row['dst_port'] != ''],
                'protocol' : row['protocol'],
                'length' : int(row['length']),
                'info' : row['info'],
                'dir' : 'NA'
                }

                packets.append(packet)

        csv_file.close()
        os.remove(filepath)

        return packets


def __main():
    thread1 = threading.Thread(target=create_profiles,args=('t1', ))
    thread1.start()

    file_queue = queue.Queue()
    global writeHeader

    event_handler = Handler(file_queue)
    observer = Observer()
    observer.schedule(event_handler, './', recursive=False)
    print("About to start observer")
    observer.start()

    try: 
        while True:
            if file_queue.qsize() > 0 and has_profiles == False:
                profile(file_queue.get())
            
            if file_queue.qsize() > 0:
                filter_anomalies(file_queue.get())
                writeHeader = False
            time.sleep(5)

    except KeyboardInterrupt: 
        observer.stop() 
        print("Observer Stopped") 
  
    observer.join()

    

if __name__ == '__main__':
    __main()
