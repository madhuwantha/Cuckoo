import os
import csv
import pandas as pd

def read_traffic(filename):
    if (os.path.exists('../'+filename)):
        packets = []
        filepath = os.path.dirname(os.getcwd())+'/'+filename
        print(filepath)
        csv_file = open(filepath, mode='r')
        csv_reader = csv.DictReader(csv_file, fieldnames=['no','time', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'length', 'info'])
            
        for row in csv_reader:
            packet = {
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

        df = pd.DataFrame(packets)
        return df

print(read_traffic('fyptraffic16.csv'))