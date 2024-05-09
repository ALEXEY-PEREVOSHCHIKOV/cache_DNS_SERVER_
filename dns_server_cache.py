import pickle
import socket
import threading
import time
import dnslib

DNS_PORT = 53
HOST_IP = '127.0.0.1'
REMOTE_DNS_SERVER = '8.8.8.8'
CACHE = {}


class DnsObject:
    def __init__(self, ttl, data):
        self._init_time = time.time()
        self.ttl = ttl
        self.data = data

    def ttl_remaining(self):
        passed_time = int(time.time() - self._init_time)
        return max(0, self.ttl - passed_time)

    def is_expired(self):
        return self.ttl_remaining() == 0


def is_domain_cached(response):
    return response.q.qname.label in CACHE


def is_answer_cached(response):
    return response.q.qtype in CACHE[response.q.qname.label]


def cache_response(response):
    data = response.ar + response.auth + response.rr
    rtype = data[0].rtype
    ttl = data[0].ttl
    dns_object = DnsObject(3, data)
    if not is_domain_cached(response):
        CACHE[response.q.qname.label] = {rtype: dns_object}
    else:
        CACHE[response.q.qname.label][rtype] = dns_object


def get_cached_data(response):
    return CACHE[response.q.qname.label][response.q.qtype]


def add_cached_data_to_response(response):
    data = get_cached_data(response)
    for addr in data.data:
        response.add_answer(
            dnslib.RR(rname=response.q.qname, rclass=response.q.qclass, rtype=response.q.qtype,
                      ttl=data.ttl_remaining(), rdata=addr.rdata)
        )


def delete_expired_responses():
    while True:
        time.sleep(1)
        with threading.Lock():
            for answer_set in CACHE.values():
                inactive = list()
                for data_type in answer_set:
                    if answer_set[data_type].is_expired():
                        inactive.append(data_type)
                for i in range(len(inactive)):
                    answer_set.pop(inactive[i])


def start_dns_server(server_socket, remote_server_socket):
    try:
        while True:
            try:
                query_data, client_addr = server_socket.recvfrom(10000)
                parsed_query = dnslib.DNSRecord.parse(query_data)
                with threading.Lock():
                    if is_domain_cached(parsed_query):
                        if is_answer_cached(parsed_query):
                            print("Cached!")
                            add_cached_data_to_response(parsed_query)
                            server_socket.sendto(parsed_query.pack(), client_addr)
                            continue
                    remote_server_socket.send(query_data)
                    response_data, _ = remote_server_socket.recvfrom(10000)
                    parsed_response = dnslib.DNSRecord.parse(response_data)
                    cache_response(parsed_response)
                    server_socket.sendto(response_data, client_addr)
                    print("Processed...")
            except socket.timeout:
                pass
    except KeyboardInterrupt:
        print("KeyboardInterrupt received. Shutting down gracefully.")
    except Exception as ex:
        print(f"An error occurred: {ex}")


if __name__ == '__main__':
    try:
        with open('dns_cache.file', 'rb') as file:
            prev_cache = pickle.loads(file.read())
            CACHE = prev_cache
    except Exception as ex:
        pass

    threading.Thread(target=delete_expired_responses, daemon=True).start()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as remote_server_socket:
                server_socket.bind((HOST_IP, DNS_PORT))
                remote_server_socket.connect((REMOTE_DNS_SERVER, DNS_PORT))
                server_socket.settimeout(1.0)
                remote_server_socket.settimeout(1.0)
                start_dns_server(server_socket, remote_server_socket)
    except socket.error:
        print(f'Connection failed: {REMOTE_DNS_SERVER}:{DNS_PORT}')
    except OSError:
        print(f'Busy: {HOST_IP}:{DNS_PORT}')

    try:
        with open('dns_cache.file', 'wb') as file:
            file.write(pickle.dumps(CACHE))
    except Exception as ex:
        print(ex)
