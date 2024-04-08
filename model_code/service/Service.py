class Service():
    def __init__(self, name):
        self.name = name

    
    def create_dns_record(self, type, qname, rdata):
        raise NotImplementedError("create_dns_record not implemented")
    
    
    def execute(self):
        raise NotImplementedError("execute not implemented")