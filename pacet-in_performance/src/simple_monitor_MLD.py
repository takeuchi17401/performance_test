from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv6, icmpv6
from ryu.lib.ofp_pktinfilter import packet_in_filter, RequiredTypeFilter
from ryu.lib.packet import ethernet
from ryu.lib import hub
import datetime
import csv

class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    packet_in_cnt = int()
    packet_in_cnt_s = int()

    Request_statsCsv = '/root/ryu/ryu/app/Request_stats.csv'
    EventOFPFlowStatsReplyCsv = './EventOFPFlowStatsReply.csv'
    EventOFPPortStatsReplyCsv = './EventOFPPortStatsReply.csv'
    EventOFPPacketInCsv = '/root/ryu/ryu/app/EventOFPPacketIn.csv'

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        ###CSV_TILE Create (Request_statsCsv)
#        list = []
#        readfile = open(self.Request_statsCsv, 'r')
#        list = readfile.readlines()
#        if len(list) == 0:
        writfile = open(self.Request_statsCsv, 'a')
        csvWriter = csv.writer(writfile)
        titelData = []
        titelData.append('run_time')
        titelData.append('packet_in_cnt')
        titelData.append('packet_in_cnt/s')
        csvWriter.writerow(titelData)
        writfile.close

#        readfile.close

        ###CSV_TILE Create (EventOFPFlowStatsReplyCsv)
#        list = []
#        readfile = open(self.EventOFPFlowStatsReplyCsv, 'r')
#        list = readfile.readlines()
#        if len(list) == 0:
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

#        readfile.close

        ###CSV_TILE Create (EventOFPPortStatsReplyCsv)
#        list = []
#        readfile = open(self.EventOFPPortStatsReplyCsv, 'r')
#        list = readfile.readlines()
#        if len(list) == 0:
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

#        readfile.close

        ###CSV_TILE Create (EventOFPPacketInCsv)
#        list = []
#        readfile = open(self.EventOFPPacketInCsv, 'r')
#        list = readfile.readlines()
#        if len(list) == 0:
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

#        readfile.close

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    @packet_in_filter(RequiredTypeFilter, args={'types': [ethernet.ethernet,ipv6.ipv6,icmpv6.icmpv6,]})
    def _packet_in_handler(self, ev):
        pkt = packet.Packet(ev.msg.data)
        print(pkt)
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
#        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
#                                  in_port=in_port, actions=actions, data=data)
#        datapath.send_msg(out)
