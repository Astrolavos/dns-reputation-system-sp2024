class Record():
    def __init__(self, hostname, rtype, rdata, ttl):
        self.name = "domain_name"
        self.hostname = hostname
        self.rtype = rtype
        self.rdata = rdata
        self.ttl = ttl

        self.operations = []

    def get_feature_vector():
        pass

    
    def __repr__(self):
        return "(" + self.hostname + ", " + self.rtype + ", " + self.rdata + ", " + str(self.ttl) + ")"
    
    def __eq__(self, item):
        return item.hostname == self.hostname and item.rtype == self.rtype and item.rdata == self.rdata and item.ttl == self.ttl
    
    def __hash__(self):
        return hash((self.hostname, self.rtype, self.rdata, self.ttl))