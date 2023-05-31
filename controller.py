from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import event, switches
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp

from dhcp import DHCPServer

class ControllerApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        Event handler indicating a switch has come online.
        """

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        """
        Event handler indicating a switch has been removed
        """


    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        """
        Event handler indiciating a host has joined the network
        This handler is automatically triggered when a host sends an ARP response.
        """ 
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        Event handler indicating a link between two switches has been added
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating when a link between two switches has been deleted
        """
        # TODO:  Update network topology and flow rules
   
        

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        This includes links for hosts as well as links between switches.
        """
        # TODO:  Update network topology and flow rules

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        每当RYU控制器收到OpenFlow协议中的packet_in消息时，packet_in_handler函数就会被调用，
        因为这个函数被注册到装饰器set_ev_cls中，并且装饰器将packet_in_handler注册到packet_in消息上，每当收到packet_in消息时就调用该函数

        """
        try:
            msg = ev.msg  # 每一个事件类ev中都有msg成员，用于携带触发事件的数据包
            datapath = msg.datapath  # 已经格式化的msg其实就是一个packet_in报文，msg.datapath直接可以获得packet_in报文的datapath结构
            # datapath用于描述一个交换网桥，也是和控制器通信的实体单元
            # datapath.send_msg()函数用于发送数据到指定datapath
            # 通过datapath.id可获得dpid数据
            pkt = packet.Packet(data=msg.data)
            ofproto = datapath.ofproto  # datapath.ofproto对象是一个OpenFlow协议数据结构的对象，成员包含OpenFlow协议的数据结构，如动作类型OFPP_FLOOD
            parser = datapath.ofproto_parser  # datapath.ofp_parser则是一个按照OpenFlow解析的数据结构。
            inPort = msg.in_port

            if pkt.get_protocols(arp.arp):
                pkt_arp = pkt.get_protocol(arp.arp)
                pkt_eth = pkt.get_protocol(ethernet.ethernet)
                # TODO: handle other protocols like ARP
                if pkt_arp.src_ip == pkt_arp.dst_ip:  # arping, update arp table
                    self.arp_table[pkt_arp.src_ip] = pkt_arp.src_mac
                elif self.arp_table.get(pkt_arp.dst_ip):
                    req_mac = self.arp_table.get(pkt_arp.dst_ip)
                    arp_pkt = packet.Packet()
                    arp_pkt.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype,
                                                           dst=pkt_eth.src, src=req_mac))
                    arp_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                                 src_mac=req_mac, src_ip=pkt_arp.dst_ip,
                                                 dst_mac=pkt_arp.src_mac,
                                                 dst_ip=pkt_arp.src_ip))
                    arp_pkt.serialize()
                    parser = datapath.ofproto_parser
                    actions = [parser.OFPActionOutput(inPort)]
                    ofproto = datapath.ofproto

                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_pkt)
                    datapath.send_msg(out)

            elif pkt.get_protocols(dhcp.dhcp):
                DHCPServer.handle_dhcp(datapath, inPort, pkt)
        except Exception as e:
            self.logger.error(e)
    
