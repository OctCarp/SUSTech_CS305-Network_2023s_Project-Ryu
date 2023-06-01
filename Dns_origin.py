from dnslib import *
from dnslib.server import DNSServer, DNSHandler, BaseResolver


class MyHandler(DNSHandler):

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def handle(self):
        # 在这里处理DNS请求的逻辑
        data = self.request[0]  # 获取请求数据

        # 解析DNS请求
        request = DNSRecord.parse(data)

        qname = request.q.qname
        qtype = request.q.qtype

        # 打印接收到的DNS请求信息
        print(f"Received DNS query for {qname} ({QTYPE[qtype]}) from {self.client_address[0]}")

        # 构造DNS响应
        reply = request.reply()

        # reply = request.reply()

        if qtype == QTYPE.A:
            # 处理A记录查询
            # 在这里添加你的A记录查询逻辑
            reply.add_answer(RR(qname, qtype, rdata=A("127.0.0.1")))
        elif qtype == QTYPE.AAAA:
            # 处理AAAA记录查询
            # 在这里添加你的AAAA记录查询逻辑
            reply.add_answer(RR(qname, qtype, rdata=AAAA("::1")))
        elif qtype == QTYPE.NS:
            # 处理NS记录查询
            # 在这里添加你的NS记录查询逻辑
            reply.add_answer(RR(qname, qtype, rdata=A("ns.example.com")))
            pass
        elif qtype == QTYPE.CNAME:
            # 处理CNAME记录查询
            # 在这里添加你的CNAME记录查询逻辑
            reply.add_answer(RR(qname, qtype, rdata=A("cname.example.com")))
            pass
        elif qtype == QTYPE.MX:
            # 处理MX记录查询
            # 在这里添加你的MX记录查询逻辑
            reply.add_answer(RR(qname, qtype, rdata=A("mail.example.com")))
            pass
        else:
            # 对于不支持的查询类型，返回相应的错误响应
            reply.header.rcode = RCODE.NXDOMAIN
        # 发送DNS响应给客户端
        self.send_response(reply)

    def send_response(self, reply):
        # 将DNS响应发送给客户端
        self.server.socket.sendto(reply.pack(), self.client_address)


MyDNSserver = DNSServer(resolver=BaseResolver, handler=MyHandler, port=53, address="0.0.0.0")


if __name__ == '__main__':

    try:
        print("Starting DNS server...")
        print("Starting DNS server successfully.")
        MyDNSserver.start()
        while True:
            pass
    except KeyboardInterrupt:
        pass
    finally:
        print("Closing DNS server...")
        MyDNSserver.stop()
        print("Closing DNS server successfully.")
