from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from dnslib import DNSRecord, RR, QTYPE, A, CNAME
from dnslib import *
from dnslib.server import DNSServer, DNSHandler, BaseResolver


class DNS_Server():

    def reply_packet(self, request):

        r = request.reply()

        if not request.querys:
            print("ERROR: Blank request.")
            return r

        for query in request.querys:
            name = query.get_qname
            type = query.qtype
            print(f"Received DNS query for {name} ({QTYPE[type]}) from {query.client_address[0]}")

            if type == QTYPE.A:
                # 处理A记录查询
                # 在这里添加你的A记录查询逻辑
                r.add_answer(RR(name, type, rdata=A("127.0.0.1")))
            elif type == QTYPE.AAAA:
                # 处理AAAA记录查询
                # 在这里添加你的AAAA记录查询逻辑
                r.add_answer(RR(name, type, rdata=AAAA("::1")))
            elif type == QTYPE.NS:
                # 处理NS记录查询
                # 在这里添加你的NS记录查询逻辑
                r.add_answer(RR(name, type, rdata=A("ns.example.com")))
                pass
            elif type == QTYPE.CNAME:
                # 处理CNAME记录查询
                # 在这里添加你的CNAME记录查询逻辑
                r.add_answer(RR(name, type, rdata=A("cname.example.com")))
                pass
            elif type == QTYPE.MX:
                # 处理MX记录查询
                # 在这里添加你的MX记录查询逻辑
                r.add_answer(RR(name, type, rdata=A("mail.example.com")))
                pass
            else:
                # 对于不支持的查询类型，返回相应的错误响应
                r.header.rcode = RCODE.NXDOMAIN
            # 发送DNS响应给客户端

        return r

    def dns_handler(self, datapath, pkt, port):
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        request = DNSRecord.parse(pkt.protocols[-1])

        if request.questions:
            pkt_ethernet_resp = pkt_ethernet
            pkt_ethernet_resp.src = pkt_ethernet_resp.dst
            pkt_ethernet_resp.dst = pkt_ethernet_resp.src

            pkt_ipv4_resp = pkt_ipv4
            pkt_ipv4_resp.src = pkt_ipv4_resp.dst,
            pkt_ipv4_resp.dst = pkt_ipv4_resp.src
            pkt_ipv4_resp.total_length = 0

            response = packet.Packet()
            response.add_protocol(pkt_ethernet_resp)
            response.add_protocol(pkt_ipv4_resp)
            reply_payload = DNS_Server.reply_packet(request).pack()
            response.add_protocol(reply_payload)
            response.serialize()

            return response

