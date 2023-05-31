## SUSTech_CS305-Network_2023s_Project-SDN

#### Teammates：徐春晖，郭健阳，彭子燊

> The source code is hosted on GitHub and will be open-sourced based on the **MIT License** after the project deadline. The access link is:
>
> https://github.com/OctCarp/SUSTech_CS305-Network_2023s_Project-SDN

------

### Developers

| Name       | SID          | Responsible for | Rate |
| ---------- | ------------ | --------------- | ---- |
| **徐春晖** | **12110304** | DHCP            |      |
| **郭健阳** | **12111506** |                 |      |
| **彭子燊** | **12110502** |                 |      |

### Project Instruction

This project requires the use of **Mininet** for network topology simulation and **Ryu Controller** as the controller to implement a simple SDN simulation. DHCP and shortest path routing functions are required.

### Function Display

### DHCP 

This software implements a simple DHCP server, allocates IP addresses to broadcast hosts from a given IP pool, and avoids duplication.  A simple lease information feature is implemented as well.

#### Utils

First, we use two function to implement conversion between IP address string and 32-bit numbers

```python
def ip_to_int(ip_address):
    ip = ip_address.split('.')
    return (int(ip[0]) << 24) + (int(ip[1]) << 16) + (int(ip[2]) << 8) + int(ip[3])


def int_to_ip(num):
    return f"{num >> 24}.{(num >> 16) & 0xff}.{(num >> 8) & 0xff}.{num & 0xff}"
```

Thus, we can convert IP address strings like `'x.x.x.x'` to a 32 bit number and vice versa.

#### Static Info and fuction

Then, we set some informations for DHCP server:

```python
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

    offer_byte = struct.pack('>B', dhcp.DHCP_OFFER)
    ack_byte = struct.pack('>B', dhcp.DHCP_ACK)
```

We use this function below to check whether a new IP for new client is OK, or it is already exist a mapping. Then we return a IP address available, or `'0.0.0.0'` for not available.

```python
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
```

#### Generate Offer and ACK packet

Then we handle the DHCP Offer Packet after DHCP Discover. The following code shows the details.

```python
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
```

Because we handle the `DHCP_REQUESTED_IP_ADDR_OPT`, so the implementation of DHCP ACK is very similar to DHCP Offer, we just need to change `DHCP_MESSAGE_TYPE_OPT` to `5` in byte, which means this packet is a DHCP ACK. For brevity, we will not show the code this time.

### DHCP Test

#### Basic 1

We use wireshark with GUI  to capture the DHCP packets.

For basic test, we have two host, need 8 packets in total to complete IP allocation twice.

![test1_init_total](img_dhcp/test1_init_total.png)

Packet 2 in detail, this is a valid DHCP offer package:

![test1_offer](img_dhcp/test1_offer.png)

Packet 4 in detail, this is a valid DHCP ACK package, including the lease time information:

![test1_ack](img_dhcp/test1_ack.png)

And it is the same for client 2.

#### Lease Time

And we implement DHCP lease time. About 70 s. The error is about TCP caputure, it doesn't matter,

![test1_lease_total](img_dhcp/test1_lease_total.png)

By the time is reached, the client will send a renewal DHCP Request packet, and the server will renew and give feedback with the correct IP, like packet 9 and 10: 

![test1_renew_request](img_dhcp/test1_renew_request.png)

If the lease end time has already passed, the client will send a DHCP Discover with request IP, and the server will renew and give feedback with the correct IP as well, like packet 11 and 12: 

![test1_renew_dicover](img_dhcp/test1_renew_dicover.png)

#### Basic 2

We created 6 DHCP clients, but only assigned the start and end IP of `192.168.1.11` - `192.168.1.14` for the IP pool, which means two client will not have a available IP.

![test2_total](img_dhcp/test2_total.png)

Packet 16, the ACK for the fourth client, is available.

![test2_fourth](img_dhcp/test2_fourth.png)

But the fifth and sixth client will not have available IP, just `0.0.0.0`, because the IP pool has already full.

Replying the Offer packet is only for the display and endding the test, but in fact this IP is invalid.

![test2_out_end](img_dhcp/test2_out_end.png)

In the above display, because of the mapping between IP and MAC, no duplicate IP will be allocated.

This is a brief demonstration of the DHCP function.



## Shortest path switching

### Code

- function 'update_topo', update the topology structure each time wo do modification operations.

```python
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
```

- function 'shortest', get shortest path according to the given src and dst, containing the switch id and the port it send packet out of each switch in the shortest path.

```python
def shortest(self, src_sw, dst_sw, dst_port):
    if not self.port_state[(dst_sw, dst_port)]:
        return None

    if src_sw == dst_sw:
        return [(dst_sw, dst_port)]

    dis = {}
    fa = {}

    nodes = self.swids
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
```



### Test

#### basic test case

##### 1.initial topology structure

![topo_example](img_sp/topo_example.png)

##### 2.the shortest path between any two hosts and length between any two switches

![SP_basic_test](img_sp/SP_basic_test.png)

##### 3.use `pingall` to verify connectivity between all hosts

![SP_basic_test_2](img_sp/SP_basic_test_2.png)



#### complex test case

##### 1.initial topology structure

![SP_complex_test_12](img_sp/SP_complex_test_12.png)

##### 2.the shortest path between any two hosts and length between any two switches

- Overall

  ![SP_complex_test_1](img_sp/SP_complex_test_1.png)

- Add Host（Initial）

  ![SP_complex_test_2](img_sp/SP_complex_test_2.png)

- Delete Switch

  before delete switch s8：

  ![SP_complex_test_3](img_sp/SP_complex_test_3.png)

  after delete switch s8：

  ![SP_complex_test_5](img_sp/SP_complex_test_5.png)

- Add Switch

  before add switch s1：

  ![SP_complex_test_9](img_sp/SP_complex_test_9.png)

  after add switch s1：

  ![SP_complex_test_10](img_sp/SP_complex_test_10.png)

- Delete Link

  before delete link s3->s7：

  ![SP_complex_test_3](img_sp/SP_complex_test_3.png)

  after delete link s3->s7：

  ![SP_complex_test_4](img_sp/SP_complex_test_4.png)

- Add Link

  before add link s5->s8：

  ![SP_complex_test_7](img_sp/SP_complex_test_7.png)

  after add link s5->s8：

  ![SP_complex_test_8](img_sp/SP_complex_test_8.png)

- Modify Port

  before disable port 3 in switch 3（to switch 8）：

  ![SP_complex_test_3](img_sp/SP_complex_test_3.png)

  after disable port 3 in switch 3：

  ![SP_complex_test_6](img_sp/SP_complex_test_6.png)

  after enable port 3 in switch 3 again：

  ![SP_complex_test_3](img_sp/SP_complex_test_3.png)

##### 3.use `pingall` to verify connectivity between all hosts

![SP_complex_test_11](img_sp/SP_complex_test_11.png)





