import time 
from watchdog.observers import Observer 
from watchdog.events import FileSystemEventHandler
import queue
from Shell import Shell
import pandas as pd
import os
import subprocess
import pyshark
import csv

class OnMyWatch: 
    # Set the directory on watch
    watchDirectory = "./"
  
    def __init__(self): 
        self.observer = Observer()
        self.queue = queue.Queue() 
  
    def run(self, dfQueue): 
        event_handler = Handler(self.queue, dfQueue) 
        self.observer.schedule(event_handler, self.watchDirectory, recursive = True) 
        self.observer.start() 
        try: 
            while True: 
                time.sleep(5)

        except: 
            self.observer.stop() 
            print("Observer Stopped") 
  
        self.observer.join()

class Handler(FileSystemEventHandler):

    def __init__(self, queue, dfQueue):
        self.df_queue = dfQueue
        self.queue = queue
        self.shell = Shell() 
   
    def on_any_event(self, event):
        if event.is_directory: 
            return None
  
        elif event.event_type == 'created': 
            # Event is created, you can process it now 
            print("Watchdog received created event - % s." % event.src_path)

            if('data' in str(event.src_path)):
                self.queue.put(str(event.src_path)[2:])
                print(self.queue.qsize())
            if(self.queue.qsize() > 1):
                file = self.queue.get()
                csv_file_name = 'traffic'+file[5:-5]+'.csv'

                self.shell.execute("echo \"1996\" |  sudo -S tshark -r " + file + " -T fields -E separator=, -E quote=d -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e _ws.col.SourcePort -e _ws.col.Destination -e _ws.col.DestinationPort -e _ws.col.Protocol -e _ws.col.Length -e _ws.col.Info > " + csv_file_name)

                packets = []

                csv_file = open(csv_file_name, mode='r')
                csv_reader = csv.DictReader(csv_file, fieldnames=['no','time', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'length', 'info'])
            
                for row in csv_reader:
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
                os.remove(csv_file_name)

                df = pd.DataFrame(packets)
                self.df_queue.put(df)
              