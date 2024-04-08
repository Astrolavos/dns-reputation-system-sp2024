import tldextract
from objects.Zone import Zone

class Graph():
    def __init__(self, domains=[], ips=[], zones=[]):
        self.domains = set(domains)
        self.domains_map = {[x.name for x in domains]: x for x in domains}
        self.ips = set(ips)
        self.ips_map = {[x.ip for x in ips]: x for x in ips}
        self.zones = set(zones)
        self.zones_map = {[x.zone for x in zones]: x for x in zones}
 
        self.tld_extract = tldextract.TLDExtract(include_psl_private_domains=True)

    
    def add_domain(self, domain):
        if domain in self.domains:
            raise Exception("Domain already in graph")
        self.domains.add(domain)
        self.domains_map[domain.name] = domain
        
        zone_2ld = domain.get_2ld()
        zone_3ld = domain.get_3ld()

        if self.get_zone(zone_2ld) is None:
            zone = Zone(zone_2ld)
            self.add_zone(zone)
            domain.zone_2ld = zone
        else:
            zone = self.get_zone(zone_2ld)
            domain.zone_2ld = zone

        if self.get_zone(zone_3ld) is None:
            zone = Zone(zone_3ld)
            self.add_zone(zone)
            domain.zone_3ld = zone
        else:
            zone = self.get_zone(zone_3ld)
            domain.zone_3ld = zone

        
    def add_zone(self, zone):
        if zone in self.zones:
            raise Exception("Zone already in graph")
        # self.zones.add(zone)
        self.zones_map[zone.name] = zone
        
    def add_ip(self, ip):
        if ip.ip in self.ips_map:
            raise Exception("IP already in graph")
        # self.ips.add(ip)
        self.ips_map[ip.ip] = ip
        
    def get_domain(self, domain_name):
        if domain_name not in self.domains_map:
            return None
        return self.domains_map[domain_name]
    
    def get_ip(self, ip_addr):
        if ip_addr not in self.ips_map:
            return None
        return self.ips_map[ip_addr]
 
    def get_zone(self, zone_name):
        if zone_name not in self.zones_map:
            return None
        return self.zones_map[zone_name]
    