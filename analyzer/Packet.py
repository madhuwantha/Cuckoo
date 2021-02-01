class Device(object):

    def __init__(self, time, src_ip, src_port, dst_ip, dst_port, protocol, length, info ):
        self.time = time  
        self.src_ip = src_ip  
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.info = info 