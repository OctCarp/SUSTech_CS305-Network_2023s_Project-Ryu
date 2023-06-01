from ryu.base import app_manager
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.controller import ofp_event
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class FirewallApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FirewallApp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 添加默认的流表规则，将所有数据包转发到控制器处理
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # 创建流表规则
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        # 解析接收到的数据包
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # 忽略非以太网数据包
        if not eth_pkt:
            return

        # 获取源MAC地址和目标MAC地址
        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst

        # 在mac_to_port字典中记录源MAC地址和端口的映射关系
        if datapath.id not in self.mac_to_port:
            self.mac_to_port[datapath.id] = {}
        self.mac_to_port[datapath.id][src_mac] = in_port

        # 检查防火墙规则并决定是否阻止数据包
        if self.firewall_check(src_mac, dst_mac):
            # 阻止数据包
            return

        # 根据目标MAC地址查找端口并发送数据包
        if dst_mac in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][dst_mac]
        else:
            # 若目标MAC地址未知，则向所有端口发送数据包（广播）
            out_port = ofproto.OFPP_FLOOD

        # 创建流表规则将数据包转发到相应的端口
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def firewall_check(self, src_mac, dst_mac):


        # 示例规则：阻止源MAC地址为00:00:00:00:00:01的数据包
        if src_mac == '00:00:00:00:00:01':
            return True

        return False
