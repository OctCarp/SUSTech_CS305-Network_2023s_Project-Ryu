from ryu.lib import addrconv
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp

import struct
from util import int_to_ip
from util import ip_to_int


class Config():
    # don't modify, a dummy mac address for fill the mac entry
    controller_macAddr = '7e:49:b3:f0:f9:99'
    dns = '8.8.8.8'  # don't modify, just for the dns entry
    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.100'  # can be modified
    netmask = '255.255.255.0'  # can be modified
    # Todo: Virtual machine IP
    server_ip = '192.168.43.131'
    lease_time = 70
    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bonus function.


class DHCPServer():
    #  class variables
    hardware_addr = Config.controller_macAddr
    server_ip = Config.server_ip
    dns = Config.dns
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    start_ip_i = ip_to_int(start_ip)  # 32 bits number for start IP
    end_ip_i = ip_to_int(end_ip)  # 32 bits number for start IP
    netmask = Config.netmask
    lease_time = Config.lease_time  # default lease time

    ip_mac = {}  # Map between IP and host MAC
    for i in range(start_ip_i, end_ip_i + 1):  # initialization
        ip_mac[i] = 'ok'  # If it is 'OK', meanings the IP is available

    # do some initialization for byte type data below
    server_ip_byte = addrconv.ipv4.text_to_bin(server_ip)
    netmask_byte = addrconv.ipv4.text_to_bin(netmask)
    dns_byte = addrconv.ipv4.text_to_bin(dns)
    lease_time_byte = struct.pack('>I', lease_time)

    # nack_byte = struct.pack('>B', )
    offer_byte = struct.pack('>B', dhcp.DHCP_OFFER)
    ack_byte = struct.pack('>B', dhcp.DHCP_ACK)

    @classmethod
    def check_ip_mac(cls, req_ip_i, client_mac):
        ip_return = '0.0.0.0'
        if (not req_ip_i == 0) and (cls.ip_mac[req_ip_i] == client_mac or cls.ip_mac[req_ip_i] == 'ok'):
            # if it has required IP and it is available
            for ip_i in cls.ip_mac:
                if cls.ip_mac[ip_i] == client_mac:
                    cls.ip_mac[ip_i] = 'ok'  # clear the previous IP info for this client
            cls.ip_mac[req_ip_i] = client_mac
            ip_return = int_to_ip(req_ip_i)  # return the IP string
        else:
            has_mac = False
            for ip_i in cls.ip_mac:
                if cls.ip_mac[ip_i] == client_mac:
                    ip_return = int_to_ip(ip_i)  # has previous IP information for the client
                    has_mac = True
                    break
            if not has_mac:
                for ip_i in cls.ip_mac:
                    if cls.ip_mac[ip_i] == 'ok':  # has available IP for new MAC
                        cls.ip_mac[ip_i] = client_mac
                        ip_return = int_to_ip(ip_i)
                        break
        return ip_return  # return IP string in the end

    @classmethod
    def assemble_offer(cls, pkt):
        # get each layer for the packet
        c_eth = pkt.get_protocol(ethernet.ethernet)
        c_ipv4 = pkt.get_protocol(ipv4.ipv4)
        c_udp = pkt.get_protocol(udp.udp)
        c_dhcp = pkt.get_protocol(dhcp.dhcp)

        client_mac = c_eth.src  # get client MAC for IP-MAC mapping

        offer_pkt = packet.Packet()
        offer_pkt.add_protocol(ethernet.ethernet(
            ethertype=c_eth.ethertype,  # sync
            dst=client_mac,  # client mac
            src=cls.hardware_addr  # controller mac
        ))

        offer_pkt.add_protocol(ipv4.ipv4(
            version=c_ipv4.version,  # sync
            proto=c_ipv4.proto,  # sync
            src=cls.server_ip,  # dhcp server ip
            dst='255.255.255.255'  # broadcast addr
        ))

        offer_pkt.add_protocol(udp.udp(
            src_port=c_udp.dst_port,  # port 67
            dst_port=c_udp.src_port  # port 68
        ))

        req_ip_i = 0

        for opt in c_dhcp.options.option_list:
            if opt.tag == dhcp.DHCP_REQUESTED_IP_ADDR_OPT:  # if it has required IP address
                req_ip_i = int.from_bytes(opt.value, byteorder='big')  # unpack IP information

        offer_return_ip = cls.check_ip_mac(req_ip_i, client_mac)  # get IP for client

        offer_pkt.add_protocol(dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,  # 2
            htype=1,  # ethernet
            hlen=c_dhcp.hlen,
            xid=c_dhcp.xid,  # random transaction id, define by client
            flags=0,  # unicast
            ciaddr='0.0.0.0',
            yiaddr=offer_return_ip,  # Your (client) IP address
            siaddr=cls.server_ip,  # Server IP address
            chaddr=c_dhcp.chaddr,  # Client hardware address (MAC addr)
            options=dhcp.options([
                dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,  # set message type as offer
                            value=cls.offer_byte  # byte for number 2
                            ),
                dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                            value=cls.lease_time_byte  # add lease time info
                            ),
                dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                            value=cls.server_ip_byte  # add server identifier
                            ),
                dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT,
                            value=cls.netmask_byte  # add subnet info
                            ),
                dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                            value=cls.dns_byte  # add DNS info
                            )
            ])
        ))

        return offer_pkt  # return the packet finally

    @classmethod
    def assemble_ack(cls, pkt):
        c_eth = pkt.get_protocol(ethernet.ethernet)
        c_ipv4 = pkt.get_protocol(ipv4.ipv4)
        c_udp = pkt.get_protocol(udp.udp)
        c_dhcp = pkt.get_protocol(dhcp.dhcp)

        client_mac = c_eth.src

        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(
            ethertype=c_eth.ethertype,
            dst=client_mac,  # client mac
            src=cls.hardware_addr  # controller mac
        ))

        ack_pkt.add_protocol(ipv4.ipv4(
            version=c_ipv4.version,
            proto=c_ipv4.proto,
            src=cls.server_ip,  # dhcp server ip
            dst='255.255.255.255'  # broadcast addr
        ))

        ack_pkt.add_protocol(udp.udp(
            src_port=c_udp.dst_port,  # port 67
            dst_port=c_udp.src_port  # port 68
        ))

        req_ip_i = 0
        for opt in c_dhcp.options.option_list:
            if opt.tag == dhcp.DHCP_REQUESTED_IP_ADDR_OPT:  # required ip address
                req_ip_i = int.from_bytes(opt.value, byteorder='big')

        ack_return_ip = cls.check_ip_mac(req_ip_i, client_mac)

        ack_pkt.add_protocol(dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,
            htype=1,  # ethernet
            hlen=c_dhcp.hlen,
            xid=c_dhcp.xid,  # random transaction id, define by client
            flags=0,  # unicast
            ciaddr='0.0.0.0',
            yiaddr=ack_return_ip,  # Your (client) IP address
            siaddr=cls.server_ip,  # Server IP address
            chaddr=c_dhcp.chaddr,  # Client hardware address
            options=dhcp.options([
                dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                            value=cls.ack_byte
                            ),
                dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                            value=cls.lease_time_byte
                            ),
                dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                            value=cls.server_ip_byte
                            ),
                dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT,
                            value=cls.netmask_byte
                            ),
                dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                            value=cls.dns_byte
                            )
            ])
        ))

        return ack_pkt

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        c_dhcp = pkt.get_protocol(dhcp.dhcp)
        option = ord(
            [opt for opt in c_dhcp.options.option_list if opt.tag == 53][0].value)

        if option == dhcp.DHCP_DISCOVER:
            cls._send_packet(datapath, port, cls.assemble_offer(pkt))
        elif option == dhcp.DHCP_REQUEST:
            cls._send_packet(
                datapath, port, cls.assemble_ack(pkt))

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
