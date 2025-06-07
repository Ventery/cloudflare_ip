import ipaddress
import socket
import ssl
import time
import ipaddress
import threading
from scapy.all import IP, ICMP, sr1
import struct

threadNum = 30
all_ips = []
def expand_cidr(cidr):
    """将单个CIDR表示法的IP段展开为所有具体IP地址的列表"""
    try:
        # 创建IPv4网络对象
        network = ipaddress.IPv4Network(cidr, strict=False)
        # 生成所有可用IP地址（包括网络地址和广播地址）
        return [str(ip) for ip in network]
    except ValueError as e:
        print(f"错误: 无效的CIDR格式 {cidr} - {e}")
        return []

def process_ip_ranges(ip_ranges):
    """处理多个IP段并返回所有IP地址的列表"""
    all_ips = []
    for cidr in ip_ranges:
        cidr = cidr.strip()
        if cidr:
            ips = expand_cidr(cidr)
            all_ips.extend(ips)
    return all_ips

target_port = 443
tcp_timeout_time = 10
def calculate_checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            a = data[i]
            b = data[i + 1]
            s += (a + (b << 8))
        else:
            s += data[i]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def tls_handshake(index):
    block_size = int(len(all_ips)/threadNum)
    for i in range(block_size):
        if index*block_size + i < len(all_ips):
            target_host = all_ips[index*block_size + i]
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            timeCnt = 0
            sucssCnt = 0
            timeoutCnt = 0
            
            while timeCnt < tcp_timeout_time:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                ssl_sock = None
                is_time_out = False
                try:
                    sock.connect((target_host, target_port))
                    #print('Connected!')
                    ssl_sock = context.wrap_socket(sock, server_hostname = target_host)
                    ssl_sock.do_handshake()
                    #print('TLS handshake successful')
                    sucssCnt = sucssCnt + 1
                except socket.timeout:
                    # print(f'Connect timeout')
                    timeoutCnt = timeoutCnt + 1
                    is_time_out = True
                except socket.error as e1:
                    #print(f'Connect failed: {e1}')
                    sp = 1
                except ssl.SSLError as e2:
                    print(f'TLS handshake failed: {e2}')
                finally:
                    if ssl_sock:
                        ssl_sock.close()
                    sock.close()
                #   time.sleep(1) 
                timeCnt = timeCnt + 1
                
                if timeoutCnt >= 3:
                    #print(target_host + "Time out!")
                    break
                
                if is_time_out:
                    continue
            
            if sucssCnt>0:
                # 创建原始套接字发送ICMP请求（Windows版本）
                try:
                    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    icmp_socket.settimeout(2)
                    
                    # 构建ICMP数据包
                    icmp_type = 8  # ICMP Echo Request
                    icmp_code = 0
                    icmp_checksum = 0
                    icmp_id = threading.get_ident() & 0xFFFF  # 使用线程ID作为标识符
                    icmp_seq = 1
                    icmp_data = b'Hello, World!'
                    
                    # 构建ICMP头部（不包含校验和）
                    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                    
                    # 计算校验和
                    icmp_checksum = calculate_checksum(icmp_header + icmp_data)
                    
                    # 重新构建包含正确校验和的ICMP头部
                    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, socket.htons(icmp_checksum), icmp_id, icmp_seq)
                    
                    # 构建完整的ICMP数据包
                    icmp_packet = icmp_header + icmp_data
                    
                    # 记录发送时间
                    start_time = time.time()
                    
                    # 发送ICMP请求
                    icmp_socket.sendto(icmp_packet, (target_host, 0))
                    
                    # 接收响应
                    relay_time = -1
                    try:
                        data, addr = icmp_socket.recvfrom(1024)
                        end_time = time.time()
                        relay_time = int((end_time - start_time) * 1000)  # 转换为毫秒
                    except socket.timeout:
                        pass
                    
                    print(f'{target_host}  {sucssCnt}' + "/" +f'{timeCnt}' + "  "+ f'{((sucssCnt / timeCnt) * 100):.2f}' + "% " + str(relay_time) + "ms")
                except PermissionError:
                    print(f"{target_host} 需要管理员权限才能发送ICMP请求")
                finally:
                    if 'icmp_socket' in locals():
                        icmp_socket.close()

if __name__ == "__main__":
    # 示例IP段列表
    ip_ranges = [
    # "103.21.244.0/22",
    # "103.22.200.0/22",
    # "103.31.4.0/22",
    # "104.16.0.0/13",
    # "104.24.0.0/14",
    # "108.162.192.0/18",
    # "131.0.72.0/22",
    # "141.101.64.0/18",
    # "162.158.0.0/15",
    # "172.64.0.0/13",
    # "173.245.48.0/20",
    # "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    ]
    
    # 处理IP段并获取所有IP地址
    all_ips = process_ip_ranges(ip_ranges)
    
    # 打印结果
    print(f"共处理 {len(ip_ranges)} 个IP段,生成 {len(all_ips)} 个IP地址")
    
    for i in range(threadNum):
        t1 = threading.Thread(target=tls_handshake, args=(i,),daemon=True)
        t1.start()

    time.sleep(10000)
    
    