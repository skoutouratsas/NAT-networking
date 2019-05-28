#2162


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import udp

from operator import attrgetter
from ryu.ofproto import ether
from ryu.ofproto import inet




class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port


        if dpid == 0x1A:
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp_pkt = pkt.get_protocol(arp.arp)
                dst_ip = arp_pkt.dst_ip
                srcMac = 0#python errors
                srcIP = 0#python errors
                dstMac = 0
                dstIP = 0
                if dst_ip == '192.168.1.1' and arp_pkt.opcode==1: #reply to private
                    srcMac =  '00:00:00:00:01:01'
                    srcIP = '192.168.1.1'
                    dstMac = eth.src
                    dstIP = arp_pkt.src_ip
                    outPort = 2
                    self.send_arp_reply(datapath, srcMac, srcIP, dstMac, dstIP, outPort,msg)
                if dst_ip == '200.0.0.1' and arp_pkt.opcode==1: #arp reply to public network
                    srcMac =  '00:00:00:00:04:01'
                    srcIP = '200.0.0.1'
                    dstMac = eth.src
                    dstIP = arp_pkt.src_ip
                    outPort = 3
                    self.send_arp_reply(datapath, srcMac, srcIP, dstMac, dstIP, outPort,msg)
                return
            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                ip=pkt.get_protocol(ipv4.ipv4)
                match=0
                dst_port=0
                src_port=0
                protocol=0x011
                if (ip.dst=="192.168.1.2"):
                    dst="00:00:00:00:01:02"
                    outPort=2
                    mac_src="00:00:00:00:01:01"
                elif (ip.dst=="192.168.1.3"):
                    dst="00:00:00:00:01:03"
                    outPort=2
                    mac_src="00:00:00:00:01:01"
                elif (ip.dst=="192.168.2.2"):
                    dst="00:00:00:00:03:02"
                    outPort=1
                    mac_src="00:00:00:00:03:01"

                elif (ip.dst=="192.168.2.3"):
                    dst="00:00:00:00:03:02"
                    outPort=1
                    mac_src="00:00:00:00:03:01"
                elif (ip.dst=="200.0.0.1"):
                    dst="00:00:00:00:04:01"
                    mac_src="00:00:00:00:04:02"
                    if ip.proto==17:
                        udp_head=pkt.get_protocol(udp.udp)
                        dst_port=udp_head.dst_port
                        src_port=udp_head.src_port
                        protocol=0x11
                    elif ip.proto==6:
                        tcp_head=pkt.get_protocol(tcp.tcp)
                        dst_port=tcp_head.dst_port
                        src_port=tcp_head.src_port
                        protocol=0x06
                    outPort=dst_port
                #elif ("200.0.0" in ip.dst):
                elif ("200.0.0.2" == ip.dst):
                    dst="00:00:00:00:04:02"
                    outPort=3
                    mac_src="00:00:00:00:04:01"


                if(dst_port!=0):
                    match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800,
                            nw_dst=ip.dst,
                            nw_src=ip.src,
                            nw_proto=protocol,
                            tp_src=src_port,
                            in_port=msg.in_port)

                else:
                    match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800,
                        nw_dst=ip.dst,
                        in_port=msg.in_port)


                self.send_message(datapath,  mac_src, dst,ip.src,ip.dst,outPort,msg,match,src)
            return
        if dpid == 0x1B:
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                arp_pkt = pkt.get_protocol(arp.arp)
                dst_ip = arp_pkt.dst_ip
                srcMac =  0
                srcIP = 0
                dstMac = 0
                dstIP = 0
                if dst_ip == '192.168.2.1':
                    srcMac =  '00:00:00:00:02:01'
                    srcIP = '192.168.2.1'
                    dstMac = eth.src
                    dstIP = arp_pkt.src_ip
                    outPort = 2
                    self.send_arp_reply(datapath, srcMac, srcIP, dstMac, dstIP, outPort,msg)
                return
            elif eth.ethertype == ether_types.ETH_TYPE_IP:
                ip=pkt.get_protocol(ipv4.ipv4)
                match=0

                if (ip.dst=="192.168.1.2"):
                    dst="00:00:00:00:03:01"
                    outPort=1
                    mac_src="00:00:00:00:03:02"
                elif (ip.dst=="192.168.1.3"):
                    dst="00:00:00:00:03:01"
                    outPort=1
                    mac_src="00:00:00:00:03:02"
                elif (ip.dst=="192.168.2.2"):
                    dst="00:00:00:00:02:02"
                    outPort=2
                    mac_src="00:00:00:00:02:01"
                elif (ip.dst=="192.168.2.3"):
                    dst="00:00:00:00:02:03"
                    outPort=2
                    mac_src="00:00:00:00:02:01"
                elif ("200.0.0" in ip.dst):
                    dst="00:00:00:00:04:02"
                    outPort=1
                    mac_src="00:00:00:00:03:02"
                match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800,
                        nw_dst=ip.dst,
                        in_port=msg.in_port)

                self.send_message(datapath, mac_src, dst,ip.src,ip.dst,outPort,msg,match,0)
            return
        else :
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            match = datapath.ofproto_parser.OFPMatch(
                in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)


    def send_arp_reply(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort,msg):
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp, dstMac, dstIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionSetDlDst(dl_addr=dstMac),
                         datapath.ofproto_parser.OFPActionSetDlSrc(dl_addr=srcMac),
                         datapath.ofproto_parser.OFPActionOutput(outPort)]
        match = datapath.ofproto_parser.OFPMatch(
                in_port=msg.in_port, dl_type=0x0806,
                nw_src=srcIp,nw_dst=dstIp)
        self.add_flow(datapath, match, actions)
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    def send_message(self, datapath, srcMac,dstMac, srcIp, dstIp, outPort,msg,match,macForHost):
            src_port=0
            dst_port=0
            protocol = 0x011
            pkt = packet.Packet(msg.data)
            ip = pkt.get_protocol(ipv4.ipv4)
            pkt.get_protocol(ethernet.ethernet).src=srcMac
            pkt.get_protocol(ethernet.ethernet).dst=dstMac


            if ip.proto==17:
                udp_head=pkt.get_protocol(udp.udp)
                dst_port=udp_head.dst_port
                src_port=udp_head.src_port
                protocol=0x11
            elif ip.proto==6:
                tcp_head=pkt.get_protocol(tcp.tcp)
                dst_port=tcp_head.dst_port
                src_port=tcp_head.src_port
                protocol=0x06

            actions = [datapath.ofproto_parser.OFPActionSetDlDst(dl_addr=dstMac),
                        datapath.ofproto_parser.OFPActionSetDlSrc(dl_addr=srcMac),
                        datapath.ofproto_parser.OFPActionOutput(outPort)]


            if(dstIp=="200.0.0.2" and datapath.id==0x1A):

                pkt.get_protocol(ipv4.ipv4).src="200.0.0.1"


                actions = [datapath.ofproto_parser.OFPActionSetDlDst(dl_addr=dstMac),
                             datapath.ofproto_parser.OFPActionSetDlSrc(dl_addr=srcMac),
                             datapath.ofproto_parser.OFPActionSetNwSrc("200.0.0.1"),
                             datapath.ofproto_parser.OFPActionSetNwDst(dstIp),#try hereeeeeeeeeeeee
                             datapath.ofproto_parser.OFPActionOutput(outPort)]

                match2 = datapath.ofproto_parser.OFPMatch(in_port=outPort,
                        dl_type=0x0800,
                        nw_dst="200.0.0.1",
                        nw_proto=protocol,
                        tp_dst=src_port,
                        tp_src=dst_port)



                actions2 = [datapath.ofproto_parser.OFPActionSetDlSrc(dl_addr=dstMac),
                             datapath.ofproto_parser.OFPActionSetDlDst(dl_addr=macForHost),
                             datapath.ofproto_parser.OFPActionSetNwDst(srcIp),
                             datapath.ofproto_parser.OFPActionSetNwSrc(dstIp),
                             datapath.ofproto_parser.OFPActionOutput(msg.in_port)]

                if match2!=0:
                    self.add_flow(datapath, match2, actions2)

            if match!=0:
                self.add_flow(datapath, match, actions)

            out = datapath.ofproto_parser.OFPPacketOut(
                 datapath=datapath,
                 buffer_id=0xffffffff,
                 in_port=datapath.ofproto.OFPP_CONTROLLER,
                 actions=actions,
                 data=pkt)
            datapath.send_msg(out)


















