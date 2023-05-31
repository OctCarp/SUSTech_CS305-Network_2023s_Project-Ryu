from collections import defaultdict
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import arp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.topology.api import *

from dhcp import DHCPServer

from queue import Queue


class ControllerAPP(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerAPP, self).__init__(*args, **kwargs)
        self.arp_table = {}
        self.swids = []
        self.host_port = {}
        self.adj = defaultdict(lambda: defaultdict(lambda: None))
        self.hosts = {}
        self.port_state = {}

    def clear(self):
        self.swids = []
        self.adj = defaultdict(lambda: defaultdict(lambda: None))

    def update_topo(self):
        self.clear()
        self.swids = [sw.dp.id for sw in get_all_switch(self)]

        links_list = get_all_link(self)
        for link in links_list:
            self.adj[link.src.dpid][link.dst.dpid] = link.src.port_no
            self.adj[link.dst.dpid][link.src.dpid] = link.dst.port_no

        for cur_switch in self.swids:
            for host_mac in self.host_port.keys():
                host_swid = self.host_port[host_mac][0]
                host_port_no = self.host_port[host_mac][1]
                sw_port = self.shortest(cur_switch, host_swid, host_port_no)
                if sw_port:
                    for sw_id, out_port in sw_port:
                        dp = get_switch(self, sw_id)[0].dp
                        match = dp.ofproto_parser.OFPMatch(dl_dst=host_mac)
                        actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
                        mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, match=match,
                                                           priority=1, actions=actions)
                        dp.send_msg(mod)

                for src_mac in self.host_port.keys():
                    if self.host_port[src_mac][0] == cur_switch:
                        src_port = self.host_port[src_mac]
                        if sw_port and self.port_state[(src_port[0], src_port[1])]:
                            self.print_path(sw_port=sw_port, src_mac=src_mac, dst_mac=host_mac)
                        elif src_mac != host_mac:
                            print(f"Net is break for {src_mac} to {host_mac}")

    def print_path(self, src_mac, sw_port, dst_mac):
        if sw_port[0][0] != self.host_port[dst_mac][0]:
            cnt = -1
            info = f"src_mac: {src_mac} -> "
            for sw_id, out_port in sw_port:
                info = info + f"s{sw_id} -> "
                cnt = cnt + 1
            info = info + f"dst_mac: {dst_mac}"
            info = info + f", switch dis = {cnt}"
            print(info)

    def shortest(self, src_sw, dst_sw, dst_port):
        if not self.port_state[(dst_sw, dst_port)]:
            return None

        if src_sw == dst_sw:
            return [(dst_sw, dst_port)]

        dis = {}
        fa = {}

        nodes = self.swid
        for node in nodes:
            dis[node] = float('inf')
            fa[node] = None

        que = Queue()
        que.put(src_sw)
        dis[src_sw] = 0
        while not que.empty():
            cur = que.get()
            for sw in nodes:
                if self.adj[cur][sw] is not None and dis[sw] > dis[cur] + 1:
                    dis[sw] = dis[cur] + 1
                    fa[sw] = cur
                    que.put(sw)

        path_ids = []
        if dst_sw not in fa.keys():
            return None

        father = fa[dst_sw]
        cur = dst_sw
        while True:
            if cur == src_sw:
                path_ids.append(src_sw)
                break
            elif father is None:
                return None
            else:
                path_ids.append(cur)
                father = fa[cur]
                cur = father
        path_ids.reverse()

        sw_port = []
        for step in range(0, len(path_ids) - 1):
            out_port = self.adj[path_ids[step]][path_ids[step + 1]]
            sw_port.append((path_ids[step], out_port))
        sw_port.append((dst_sw, dst_port))
        return sw_port

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

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        print("Add Switch")
        self.update_topo()

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        print("Delete Switch")
        self.update_topo()

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        print("Add Host")
        host_mac = ev.host.mac
        self.host_port[host_mac] = (ev.host.port.dpid, ev.host.port.port_no)
        self.port_state[(ev.host.port.dpid, ev.host.port.port_no)] = True
        self.update_topo()

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        print("Add Link")
        self.update_topo()

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        print("Delete Link")
        self.update_topo()

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        print("Modify Port")
        for port in self.port_state:
            if (ev.port.dpid, ev.port.port_no) == port:
                self.port_state[(ev.port.dpid, ev.port.port_no)] = ev.port.is_live()
        self.update_topo()
