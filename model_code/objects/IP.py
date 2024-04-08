import ipaddress
import radix

class IP():


    def __init__(self, ip):
        self.ip = ip
        self.rhdns = []
        self.asn = None
        self.country = None
        self.registration_date = None
        self.prefixes = []
        self.org = None
        self.has_ptr = False
        self.registry = None

    def __eq__(self, item):
        return item.ip == self.ip
    
    def __hash__(self):
        return hash(self.ip)
    
    def __repr__(self):
        return self.ip
    
    
    def parse_ip(ip, radix_tree):
        try:
            ip = int(ip)
            ip = str(ipaddress.ip_address(ip))
        except:
            pass
        ip_obj = IP(ip)
        ip_nodes = radix_tree.search_covering(ip)
        for ip_node in ip_nodes:
            ip_obj.asn = ip_node.data["asn"]
            ip_obj.country = ip_node.data["country"]
            ip_obj.registration_date = ip_node.data["changed"]
            ip_obj.prefixes.append(ip_node.prefix)
            ip_obj.org = ip_node.data["name"] 
            ip_obj.registry = ip_node.data["registry"]
        return ip_obj
