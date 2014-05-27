import asyncore
import socket
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv6, icmpv6, vlan
from ryu.lib import hub

class EchoHandler(asyncore.dispatcher_with_send):

    def handle_read(self):
        data = self.recv(8192)
        if data:
            self.send(data)

class EchoServer(asyncore.dispatcher):

    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._send_regularly)
        self.logger.debug('__init__ : %s', self.PROTPCOL)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            pass
        else:
            sock, addr = pair
            print 'Incoming connection from %s' % repr(addr)
            handler = EchoHandler(sock)

    def _send_regularly(self):
        while(self.loop): hub.sleep(1)
        datapath = self.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        
        
        src = "11:22:33:44:55:66"
        dst = "66:55:44:33:22:11"
        srcip = "11::"
        dstip= "::11"
#        srcip = "fe80::200:ff:fe00:1"
#        dstip= "ff02::1:ff00:2"
#        10    461.902996000    fe80::200:ff:fe00:1    ff02::1:ff00:2    ICMPv6    86    Neighbor Solicitation for fe80::200:ff:fe00:2 from 00:00:00:00:00:01
        in_port = 1

        while True:
            sendpkt = self.createPacket(src, dst, srcip, dstip)
#            self.sendPacketOut(parser, datapath, in_port, actions, sendpkt.data)
            
            IPPROTO_ICMP = socket.getprotobyname('ipv6-icmp')
#            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_ICMP)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, IPPROTO_ICMP)
            while sendpkt.data:
                
                #sent_bytes = sock.sendto(sendpkt.data, ('ff38::1', 0, icmpv6.icmpv6(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY, data=icmpv6.mldv2_query(address='::'))))
                sent_bytes = sock.sendto(sendpkt.data,sa ('ff38::1', 0))
                sendpkt.data = sendpkt.data[sent_bytes:]
    
            self.logger.debug("******** send packet :\n %s\n" % (sendpkt,))
            hub.sleep(self.WAIT_TIME)

    def createPacket(self, src, dst, srcip, dstip):
        # create send packet
        sendpkt = packet.Packet()
        sendpkt.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_8021Q, dst=dst, src=src))
        sendpkt.add_protocol(vlan.vlan(pcp=0, cfi=0, vid=100, ethertype=ether.ETH_TYPE_IPV6))
        sendpkt.add_protocol(ipv6.ipv6(src=srcip, dst=dstip, nxt=inet.IPPROTO_ICMPV6))
        sendpkt.add_protocol(icmpv6.icmpv6(type_=icmpv6.ICMPV6_MEMBERSHIP_QUERY,
                                data=icmpv6.mldv2_query(address='::')))
        sendpkt.serialize()
        return sendpkt

#server = EchoServer('localhost', 8080)
asyncore.loop()