import time 
from watchdog.observers import Observer 
from watchdog.events import FileSystemEventHandler
import queue
from Shell import Shell

class OnMyWatch: 
    # Set the directory on watch
    watchDirectory = "../"
  
    def __init__(self): 
        self.observer = Observer()
  
    def run(self, file_queue): 
        event_handler = Handler(file_queue) 
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
            
              