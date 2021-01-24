from Shell import Shell
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ontrafficwatch import OnTrafficWatch


def collecting_traffic(name):
    print(str(name)+ ' Thread starts')
    shell = Shell()
    
    shell.execute("echo \"1996\" | sudo -S tcpdump -i any -v -G 20 not arp -w data-%S.pcap")

def __main():

    thread1 = threading.Thread(target=collecting_traffic,args=('t1', ))
    thread1.start()

    watch = OnTrafficWatch()
    watch.run()
if __name__ == '__main__':
    __main()
