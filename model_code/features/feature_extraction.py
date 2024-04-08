from objects.Domain import Domain
from objects.IP import IP
from sklearn.feature_extraction.text import CountVectorizer
import numpy as np
import json
import datetime
import math

class FeatureExtraction():
    def __init__(self, 
                date,
                as_radix=None, 
                rhip_list=None, 
                ip_blocklist_as=None, 
                ip_blocklist_prefix=None, 
                rhdn_list=None,
                rhip_2ld_list=None,
                rhip_3ld_list=None,
                subdomain_list=None,
                popularity_list=None,
                ptr_set=None,
                wordlist=None
        ):
        
        self.date = date
        self.as_radix = as_radix
        self.rhip_list = rhip_list
        self.ip_blocklist_as = ip_blocklist_as
        self.ip_blocklist_prefix = ip_blocklist_prefix
        self.rhdn_list = rhdn_list
        self.rhip_2ld_list = rhip_2ld_list
        self.rhip_3ld_list = rhip_3ld_list
        self.popularity_list = popularity_list
        self.ptr_set = ptr_set
        self.subdomain_list = subdomain_list
        self.wordlist = wordlist
        
        self.creation_dates = {}
        self.expiration_dates = {}
        for line in open("data/whois_data.json").readlines():
            obj = json.loads(line)
            if "date_created" in obj:
                date_created = datetime.datetime.strptime(obj["date_created"], '%Y-%m-%d')
                self.creation_dates[obj["domain"]] = date_created
        for line in open("data/rdap-data.json").readlines():
            obj = json.loads(line)
            if "creation_date" in obj:
                date_created = None
                try:
                    if type(obj["creation_date"]) is list:
                        date_created = datetime.datetime.strptime(obj["creation_date"][0].split(" ")[0], '%Y-%m-%d')
                    elif obj["creation_date"] is not None:
                        date_created = datetime.datetime.strptime(obj["creation_date"].split(" ")[0], '%Y-%m-%d')
                    else:
                        continue
                    domain_name = obj["domain_name"]
                    if type(obj["domain_name"]) is list:
                        domain_name = obj["domain_name"][0]
                    self.creation_dates[domain_name] = date_created
                except ValueError:
                    pass
        
        for line in open("data/expiration_dates.json").readlines():
            obj = json.loads(line)
            if "expiration_date" in obj:
                expiration_date = datetime.datetime.strptime(obj["expiration_date"], '%Y-%m-%d')
                domain_name = obj["domain"]
                if type(obj["domain"]) is list:
                    domain_name = obj["domain"][0]
                self.expiration_dates[domain_name] = expiration_date
        
        

    def get_feature_vector(self, domain: Domain):
        vector = {}
        
        vector.update(self.get_lexical_features(domain))
        vector.update(self.get_network_features(domain))
        vector.update(self.get_rhdn_features(domain))
        vector.update(self.get_popularity_features(domain))
        vector.update(self.get_evidence_features(domain))
        vector.update(self.get_registration_features(domain))

        return vector
    
    def get_lexical_features(self, domain: Domain):
        vector = {}
        
        vector["domain_length"] = len(domain.name) - len(domain.get_tld()) - 1
       
        vector["number_ratio"] = 0
        for char in domain.name[:-len(domain.get_tld())-1]:
            if char.isdigit():
                vector["number_ratio"] += 1
        vector["number_ratio"] /= len(domain.name)
       
        longest = 0
        for word in self.wordlist:
            if len(word) > longest and  word in domain.name:
                longest = len(word)
        vector["longest_human_readable_substring"] = longest
                
        vector["num_of_subdomains"] = len(domain.name.split("."))
         
        vector["num_of_trigrams"] = np.size(CountVectorizer(ngram_range=(3,3), analyzer='char').fit_transform([domain.get_name()]).toarray().sum(axis=0)) if len(domain.get_name()) > 2 else 0

        vector["entropy"] = self.calculate_entropy(domain.get_name())
                 
        return vector

    def get_network_features(self, domain: Domain):
        vector = {}
        
        vector["distinct_ips"] = len(domain.rhips)
        vector["distinct_asns"] = len(self.get_asns(domain.rhips))
        vector["distinct_bgp_countries"] = len(self.get_countries(domain.rhips))
        vector["distinct_bgp_prefixes"] = len(self.get_prefixes(domain.rhips))
        vector["distinct_bgp_orgs"] = len(self.get_orgs(domain.rhips))
        vector["num_ip_reg_dates_fqdn"] = len(self.get_dates(domain.rhips)) 
        vector["distinct_as_registries"] = len(self.get_registries(domain.rhips))
        
        vector["distinct_ips_2ld_zone"] = len(domain.zone_2ld.rhips)
        vector["distinct_asn_2ld_zone"] = len(self.get_asns(domain.zone_2ld.rhips))
        vector["distinct_bgp_countries_2ld_zone"] = len(self.get_countries(domain.zone_2ld.rhips))
        vector["distinct_prefixes_2ld_zone"] = len(self.get_prefixes(domain.zone_2ld.rhips))
        vector["distinct_as_names_2ld_zone"] = len(self.get_orgs(domain.zone_2ld.rhips))
        vector["num_ip_reg_dates_2ld"] = len(self.get_dates(domain.zone_2ld.rhips))
        vector["distinct_as_registries_2ld_zone"] = len(self.get_registries(domain.zone_2ld.rhips))
        
        vector["distinct_ips_3ld_zone"] = len(domain.zone_3ld.rhips)
        vector["distinct_asn_3ld_zone"] = len(self.get_asns(domain.zone_3ld.rhips))
        vector["distinct_bgp_countries_3ld_zone"] = len(self.get_countries(domain.zone_3ld.rhips))
        vector["distinct_prefixes_3ld_zone"] = len(self.get_prefixes(domain.zone_3ld.rhips))
        vector["distinct_as_names_3ld_zone"] = len(self.get_orgs(domain.zone_3ld.rhips))
        vector["num_ip_reg_dates_3ld"] = len(self.get_dates(domain.zone_3ld.rhips))
        vector["distinct_as_registries_3ld_zone"] = len(self.get_registries(domain.zone_3ld.rhips))
               
        return vector


    def get_rhdn_features(self, domain: Domain):
        vector = {}
        rhdns_of_d = [domain]
       
        for rhip in domain.rhips:
            rhdns_of_d.extend(rhip.rhdns)
        
        rhdn_names = set(list(x.name for x in rhdns_of_d))
        
        lengths = [len(rhdn) for rhdn in rhdn_names]
        
        vector["rhdn_count"] = len(rhdn_names)
        vector["rhdn_length_mean"] = round(np.mean(lengths), 10)
        vector["rhdn_length_median"] = np.median(lengths)
        vector["rhdn_length_std"] = round(float(np.std(lengths)), 10)
        
        one_grams = CountVectorizer(ngram_range=(1,1), analyzer='char').fit_transform(rhdn_names).toarray().sum(axis=0)
        two_grams = CountVectorizer(ngram_range=(2,2), analyzer='char').fit_transform(rhdn_names).toarray().sum(axis=0)
        three_grams = CountVectorizer(ngram_range=(3,3), analyzer='char').fit_transform(rhdn_names).toarray().sum(axis=0)
        
        vector["rhdn_1gram_mean"] = round(float(np.mean(one_grams)), 10)
        vector["rhdn_2gram_mean"] = round(float(np.mean(two_grams)), 10)
        vector["rhdn_3gram_mean"] = round(float(np.mean(three_grams)), 10)
        vector["rhdn_1gram_median"] = float(np.median(one_grams))
        vector["rhdn_2gram_median"] = float(np.median(two_grams))
        vector["rhdn_3gram_median"] = float(np.median(three_grams))
        vector["rhdn_1gram_std"] = round(float(np.std(one_grams)), 10)
        vector["rhdn_2gram_std"] = round(float(np.std(two_grams)), 10)
        vector["rhdn_3gram_std"] = round(float(np.std(three_grams)), 10)
            
            

        tld_counts = {}
        for rhdn in rhdns_of_d:
            tld = rhdn.get_tld()
            if tld not in tld_counts:
                tld_counts[tld] = 0
            tld_counts[tld] += 1
        
        vector["distinct_tld_count"] = len(tld_counts.keys())
        vector["avg_tld_freq"] = round(np.mean(list(tld_counts.values())) / len(rhdns_of_d), 10)
        vector["stddev_tld_freq"] = round(np.std(list(tld_counts.values())) / len(rhdns_of_d), 10)
        vector["median_tld_freq"] = round(np.median(list(tld_counts.values())) / len(rhdns_of_d), 10)
        
        if "com" in tld_counts:
            the_sum = sum(v for k, v in tld_counts.items() if k != "com")
            if the_sum == 0:
                vector["com_other_ratio"] = -1
            else:
                vector["com_other_ratio"] = round(tld_counts["com"] / the_sum, 10)
        else:
            vector["com_other_ratio"] = 0


        # print(vector)
        return vector
    
    def get_popularity_features(self, domain: Domain):        
        vector = {}
        vector["pop_1m"] = int(domain.popularity_rank <= 1000000)
        vector["pop_500k"] = int(domain.popularity_rank <= 500000)
        vector["pop_100k"] = int(domain.popularity_rank <= 100000)
        vector["pop_10k"] = int(domain.popularity_rank <= 10000)
        vector["pop_1k"] = int(domain.popularity_rank <= 1000)

        return vector
    
    def get_evidence_features(self, domain: Domain):
        vector = {}
        
        vector["ip_blocklist_asn"] = 0
        vector["ip_blocklist_bgp"] = 0
        vector["ip_blocklist_past_ips"] = 0
        
        malware_ips_set = set([item for sublist in self.ip_blocklist_as for item in sublist])
        # print("asns:", self.get_asns(domain.rhips)) 
        for asn in self.get_asns(domain.rhips):
            if str(asn) in self.ip_blocklist_as:
                vector["ip_blocklist_asn"] += len(self.ip_blocklist_as[str(asn)])
        for prefix in self.get_prefixes(domain.rhips):
            if prefix in self.ip_blocklist_prefix:
                vector["ip_blocklist_bgp"] += len(self.ip_blocklist_prefix[prefix]) 
                
        for ip in domain.rhips:
            if ip.ip in malware_ips_set:
                vector["ip_blocklist_past_ips"] += 1

        return vector

    def get_registration_features(self, domain: Domain):
        vector = {}
        if domain.creation_date is not None:
            vector["days_created_now"] = (self.date - domain.creation_date).days
        else:
            vector["days_created_now"] = -1
        if domain.expiration_date is not None and domain.creation_date is not None:
            vector["days_created_expires"] = (domain.expiration_date - domain.creation_date).days
        else:
            vector["days_created_expires"] = -1
        
        return vector
 
    def get_rr_features(self, domain: Domain):
        vector = {}

        vector["rdns_ratio"] = sum([1 if ip.has_ptr else 0 for ip in domain.rhips]) / len(domain.rhips)
        
        vector["num_of_subdomains"] = len(self.subdomain_list[domain.name]) if domain.name in self.subdomain_list else 0
        
        return vector
 

    def get_asns(self, list: [IP]):
        asn_set = set()
        for ip in list:
            asn_set.add(ip.asn)
        return asn_set
            
    def get_countries(self, list: [IP]):
        country_set = set()
        for ip in list:
            if ip.country is not None:
                country_set.add(ip.country)
        return country_set

    def get_orgs(self, list: [IP]):
        org_set = set()
        for ip in list:
            if ip.org is not None:
                org_set.add(ip.org)
        return org_set
    
    def get_prefixes(self, list: [IP]):
        prefix_set = set()
        for ip in list:
            prefix_set = prefix_set.union(set(ip.prefixes))
        return prefix_set

    def get_dates(self, list: [IP]):
        date_set = set()
        for ip in list:
            date_set.add(ip.registration_date)
        return date_set

    def get_registries(self, list: [IP]):
        registry_set = set()
        for ip in list:
            registry_set.add(ip.registry)
        return registry_set


    def calculate_entropy(self, string):
        if len(string) == 0:
            return 0.0
        
        freq_map = {}
        for char in string:
            if char in freq_map:
                freq_map[char] += 1
            else:
                freq_map[char] = 1
                
        entropy = 0.0
        total_len = len(string)
        for freq in freq_map.values():
            probability = freq / total_len
            entropy += -probability * math.log2(probability)
        
        return entropy