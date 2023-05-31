from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_0_parser
from ryu.topology.api import *


class Firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Firewall, self).__init__(*args, **kwargs)
        self.target = []
        self.target.append('00:00:00:00:00:01')

    @set_ev_cls(event.EventSwitchEnter)
    def switch_features_handler(self, ev):
        for drop_mac in self.target:
            match = ofproto_v1_0_parser.OFPMatch(dl_dst=drop_mac)
            command = ofproto_v1_0.OFPFC_ADD
            drop = ofproto_v1_0.OFPP_NONE
            actions = None
            req = ofproto_v1_0_parser.OFPFlowMod(datapath=ev.switch.dp, command=command, idle_timeout=0, hard_timeout=0,
                                                 priority=600, match=match, actions=actions)
            ev.switch.dp.send_msg(req)


