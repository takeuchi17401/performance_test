from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser, ether, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv6, icmpv6
from ryu.lib import hub
import datetime
import csv

class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # get_protocol(eth/ipv6)
    PROTPCOL = 'ipv6'
    
    packet_in_cnt = int()
    packet_in_cnt_s = int()
    
    Request_statsCsv = '/root/ryu/ryu/Request_stats.csv'
    EventOFPFlowStatsReplyCsv = '/root/ryu/ryu/EventOFPFlowStatsReply.csv'
    EventOFPPortStatsReplyCsv = '/root/ryu/ryu/EventOFPPortStatsReply.csv'
    EventOFPPacketInCsv = '/root/ryu/ryu/EventOFPPacketIn.csv'

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.debug('__init__ : %s', self.PROTPCOL)
        self.csv_title_create        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        self.logger.debug('add_flow STR : %s', self.PROTPCOL)
        
        actions = [ofproto_v1_3_parser.OFPActionOutput(ofproto_v1_3.OFPP_NORMAL)]
        instructions = [ofproto_v1_3_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
        # match
#            match = ofproto_v1_3_parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6, ip_proto=inet.IPPROTO_ICMP6)
        # miss match
        match = ofproto_v1_3_parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6, ip_proto=inet.IPPROTO_ICMP)
        flow_mod_msg = ofproto_v1_3_parser.OFPFlowMod(datapath, match=match, instructions=instructions)
        datapath.send_msg(flow_mod_msg)

        self.logger.debug('add_flow END : %s', self.PROTPCOL)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.packet_in_cnt += 1
        self.packet_in_cnt_s += 1

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        # get_protocols(ethernet)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]
        self.logger.debug('ethernet= %s ', str(pkt_eth))
        dst = pkt_eth.dst
        src = pkt_eth.src

        if self.PROTPCOL in 'ipv6':
            # get_protocols(pkt_ipv6)
            pkt_ipv6 = pkt.get_protocols(ipv6.ipv6)
            if 0 < len(pkt_ipv6):
                self.logger.debug('ipv6= %s', str(pkt_ipv6))

            # get_protocols(pkt_icmpv6)
            pkt_icmpv6 = pkt.get_protocols(icmpv6.icmpv6)
            if 0 < len(pkt_icmpv6):
                self.logger.debug('icmpv6= %s icmpv6.ND_NEIGHBOR_SOLICIT = %s' , str(pkt_icmpv6), icmpv6.ND_NEIGHBOR_SOLICIT)
                
                if pkt_icmpv6[0].type_ != icmpv6.ND_NEIGHBOR_SOLICIT:
                    return
            
        dpid = datapath
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug('packet in %s %s %s %s %s', dpid, src, dst, in_port, str(self.packet_in_cnt))

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        self.logger.debug('in_port = %s, out_port = %s, OFPP_FLOOD = %s', str(in_port), str(out_port), str(ofproto.OFPP_FLOOD))
        
        if out_port != ofproto.OFPP_FLOOD:
            
            if self.PROTPCOL in 'ipv4':
                # match
#                match = parser.OFPMatch(in_port=in_port, eth_dst=dst )
                #miss match
                match = parser.OFPMatch(in_port=in_port, eth_type=0, eth_dst=dst )
            elif self.PROTPCOL in 'ipv6' or self.PROTPCOL in 'icmpv6':
                match = parser.OFPMatch(in_port=in_port, eth_type=ether.ETH_TYPE_IPV6, ip_proto=inet.IPPROTO_ICMPV6, ipv6_dst=dst)

            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

# nofileio
        """
        now = datetime.datetime.now()
        writefile = open(self.EventOFPPacketInCsv, 'a')
        csvWriter = csv.writer(writefile)
        listData = []
        listData.append(str(now.strftime('%Y/%m/%d %H:%M:%S.') + '%04d' % (now.microsecond // 1000)))
        listData.append(str(dpid))
        listData.append(str(src))
        listData.append(str(dst))
        listData.append(str(in_port))
        listData.append(str(out_port))
        listData.append(str(self.packet_in_cnt))
        csvWriter.writerow(listData)
        writefile.close
        """

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            now = datetime.datetime.now()
            writfile = open(self.Request_statsCsv, 'a')
            csvWriter = csv.writer(writfile)
            listData = []
            listData.append(str(now.strftime('%Y/%m/%d %H:%M:%S.') + '%04d' % (now.microsecond // 1000)))
            listData.append(str(self.packet_in_cnt))
            listData.append(str(self.packet_in_cnt_s))
            csvWriter.writerow(listData)
            writfile.close

            self.packet_in_cnt_s = 0
#            for dp in self.datapaths.values():
#                self._request_stats(dp)
            hub.sleep(1)

    def _request_stats(self, datapath):
       
        self.logger.debug('packet_in_cnt=' + str(self.packet_in_cnt))
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        req = parser.OFPTableStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
       
#    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        
        now = datetime.datetime.now()

        body = ev.msg.body

        write = open(self.EventOFPFlowStatsReplyCsv, 'a')
        csvWriter = csv.writer(write)

        self.logger.debug('time                    ,'
                         'datapath        ,'
                         'in-port ,eth-dst          ,'
                         'out-port,packets ,bytes')

        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):

            self.logger.debug('%024s,%016x,%8x,%17s,%8x,%8d,%8d',
                             now.strftime('%Y/%m/%d %H:%M:%S.') + '%04d' % (now.microsecond // 1000),
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count, 
                             stat.packet_count - self.before_packet_count, stat.byte_count - self.before_byte_count)

            now = datetime.datetime.now()
            listData = []
            listData.append(str(now.strftime('%Y/%m/%d %H:%M:%S.') + '%04d' % (now.microsecond // 1000)))
            listData.append(str(dpid))
            listData.append(str(ev.msg.datapath.id))
            listData.append(str(stat.match['in_port']))
            listData.append(str(stat.match['eth_dst']))
            listData.append(str(stat.packet_count))
            listData.append(str(stat.byte_count))
            csvWriter.writerow(listData)
            
        write.close

#    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        now = datetime.datetime.now()

        body = ev.msg.body

        writfile = open(self.EventOFPPortStatsReplyCsv, 'a')
        csvWriter = csv.writer(writfile)
        
        self.logger.debug('time                    ,'
                         'datapath        ,port    ,'
                         'rx-pkts ,rx-bytes,rx-error,'
                         'tx-pkts tx-bytes,tx-error')
        for stat in sorted(body, key=attrgetter('port_no')):

            self.logger.debug('%24s,%016x,%8x,%8d,%8d,%8d,%8d,%8d,%8d', 
                             now.strftime('%Y/%m/%d %H:%M:%S.') + '%04d' % (now.microsecond // 1000),
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)

            now = datetime.datetime.now()
            listData = []
            listData.append(str(now.strftime('%Y/%m/%d %H:%M:%S.') + '%04d' % (now.microsecond // 1000)))
            listData.append(str(ev.msg.datapath.id))
            listData.append(str(stat.port_no))
            listData.append(str(stat.rx_packets))
            listData.append(str(stat.rx_bytes))
            listData.append(str(stat.rx_errors))
            listData.append(str(stat.tx_packets))
            listData.append(str(stat.tx_bytes))
            listData.append(str(stat.tx_errors))
            csvWriter.writerow(listData)

        writfile.close

    def csv_title_create():
        ###CSV_TILE Create (Request_statsCsv)
        writfile = open(self.Request_statsCsv, 'a')
        csvWriter = csv.writer(writfile)
        titelData = []
        titelData.append('run_time')
        titelData.append('packet_in_cnt')
        titelData.append('packet_in_cnt/s')
        csvWriter.writerow(titelData)
        writfile.close
        
        ###CSV_TILE Create (EventOFPFlowStatsReplyCsv)
        writfile = open(self.EventOFPFlowStatsReplyCsv, 'a')
        csvWriter = csv.writer(writfile)
        titelData = []
        titelData.append('run_time')
        titelData.append('datapath')
        titelData.append('in-port')
        titelData.append('eth-dst')
        titelData.append('packets')
        titelData.append('bytes')
        csvWriter.writerow(titelData)
        writfile.close

        ###CSV_TILE Create (EventOFPPortStatsReplyCsv)
        writfile = open(self.EventOFPPortStatsReplyCsv, 'a')
        csvWriter = csv.writer(writfile)
        titelData = []
        titelData.append('run_time')
        titelData.append('datapath')
        titelData.append('port')
        titelData.append('rx-pkts')
        titelData.append('rx-bytes')
        titelData.append('rx-error')
        titelData.append('tx-pkts')
        titelData.append('tx-bytes')
        titelData.append('tx-error')
        csvWriter.writerow(titelData)
        writfile.close

        ###CSV_TILE Create (EventOFPPacketInCsv)
        writfile = open(self.EventOFPPacketInCsv, 'a')
        csvWriter = csv.writer(writfile)
        titelData = []
        titelData.append('run_time')
        titelData.append('datapathid')
        titelData.append('src')
        titelData.append('dst')
        titelData.append('in_port')
        titelData.append('packet_in_cnt')
        csvWriter.writerow(titelData)
        writfile.close
