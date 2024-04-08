import tldextract
tld_extract = tldextract.TLDExtract(include_psl_private_domains=True)

class Domain():
    def __init__(self, name):
        self.name = name
        self.popularity_rank = -1
        self.current_records = []
        self.current_records = []
        self.rhips = []
        self.current_nameservers = []
        self.historical_nameservers = []
        
        self.creation_date = None
        self.expiration_date = None

        self.zone_2ld = None
        self.zone_3ld = None
    
        
        self.operations = []
        

    def get_feature_vector():
        pass
    
    def __eq__(self, item):
        return item.name == self.name
    
    def __hash__(self):
        return hash(self.name)

        
    # Domain utils

    def get_tld(self):
        extracted = tld_extract(self.name)
        return extracted.suffix

    def get_3ld(self):
        extracted = tld_extract(self.name)

        if len(extracted[0].split('.')) == 0: return ''
        return extracted[0].split('.')[-1] + '.' + '.'.join(extracted[-2:])

    def get_2ld(self):
        extracted = tld_extract(self.name)
        return extracted.registered_domain
   
    def get_name(self):
        extracted = tld_extract(self.name)
        str = ".".join(extracted[0:2])
        if str[0] == ".":
            return str[1:]
        return str
