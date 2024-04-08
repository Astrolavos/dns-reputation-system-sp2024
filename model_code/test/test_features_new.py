import unittest
from service.models.LocalModelService import LocalModelService
import yaml
import os
import json
import numpy as np
import math
from sklearn.feature_extraction.text import CountVectorizer
import tldextract
import pickle
import radix
from features.feature_extraction import FeatureExtraction
from objects.Domain import Domain
from objects.IP import IP
from objects.Graph import Graph
import ipaddress
import csv
from datetime import datetime

# {'avg_tld_freq': 1.0, 'com_other_ratio': None, 'ct_valid_length': 17.2666403084, 'days_created_expires': 9.0362250517, 'days_created_now': 8.980298079, 'distinct_as_2ld_zone': 1.0, 
#  'distinct_asn_3ld_zone': 1.0, 'distinct_asns': 1.0, 'distinct_bgp_countries': 1.0, 'distinct_bgp_countries_2ld_zone': 1.0, 'distinct_bgp_countries_3ld_zone': 1.0, 
#  'distinct_bgp_orgs': 1.0, 'distinct_bgp_prefixes': 1.0, 'distinct_ips': 2.1972245773, 'distinct_ips_2ld_zone': 2.1972245773, 'distinct_ips_3ld_zone': 2.1972245773, 
#  'distinct_prefixes_2ld_zone': 1.0, 'distinct_prefixes_3ld_zone': 1.0, 'distinct_tld_count': 0.6931471806, 'domain_length': 67.0, 'ip_blocklist_asn': 0.0, 
#  'ip_blocklist_bgp': 0.6931471806, 'ip_blocklist_past_ips': 0.0, 'longest_human_readable_substring': 11.0, 
# 'median_tld_freq': 1.0, 'num_ip_reg_dates_2$d': 2.1972245773, 'num_ip_reg_dates_3ld': 2.1972245773, 'num_ip_reg_dates_fqdn': 2.1972245773, 
# 'num_of_subdomains': 2.0, 'num_of_trigrams': 59.0, 'num_registries_2ld': 2.1972245773, 'num_registries_3ld': 2.1972245773, 
# 'num_registries_fqdn': 2.1972245773, 'number_ratio': 0.0447761194, 'pop_100k_falling': 0.0, 'pop_100k_null': 0.0, 'pop_100k_rising': 0.0, 
# 'pop_100k_stable': 1.0, 'pop_10k_falling': 0.0, '$op_10k_null': 1.0, 'pop_10k_rising': 0.0, 'pop_10k_stable': 0.0, 'pop_1k_falling': 0.0, 
# 'pop_1k_null': 1.0, 'pop_1k_rising': 0.0, 'pop_1k_stable': 0.0, 'pop_1m_falling': 0.0, 'pop_1m_null': 0.0, 'pop_1m$rising': 0.0, 
# 'pop_1m_stable': 1.0, 'rdns_ratio': 1.0, 'rhdn_1gram_mean': 3.0127737394, 'rhdn_1gram_median': 2.8033603809, 'rhdn_1gram_std': 3.034115275, 
# 'rhdn_2gram_mean': 1.7377634705, 'rhdn_2gram_med$an': 1.3862943611, 'rhdn_2gram_std': 1.7999001599, 'rhdn_3gram_mean': 1.5421963549, 
# 'rhdn_3gram_median': 2.0, 'rhdn_3gram_std': 1.5329093738, 'rhdn_count': 2.3978952728, 'rhdn_length_mean': 61.9, 'rhdn_$ength_median': 71.0, 
# 'rhdn_length_std': 16.2323750573, 'stddev_tld_freq': 0.0}

def ngrams(s, n=2):
    return [s[i:i+n] for i in range(len(s)-n+1)]


class TestFeatures(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        infra_config = os.environ["TEST_INFRA_PATH"]
        with open(infra_config) as f:
            cls.infra_config = yaml.load(f, Loader=yaml.FullLoader)
        plan_config = os.environ["TEST_PLAN_PATH"]
        with open(plan_config) as f:
            cls.plan_config = yaml.load(f, Loader=yaml.FullLoader)

  
    def test_features(self):
        # local_model_service = LocalModelService("Local", self.infra_config["services"]["local_model"]["path"], self.infra_config["services"]["local_model"]["ground_truth_path"])
        # feature_vector = local_model_service.get_feature_vector(Domain("www.mwasr.com"))
        feature_vector = {"ct_valid_length":29894399,"days_created_expires":2557,"days_created_now":2322,"pop_1m":1,"pop_500k":1,"pop_100k":1,"pop_10k":1,"pop_1k":1,"distinct_ips":3,"rdns_ratio":0.0,"number_ratio":0.125,"domain_length":24,"num_of_subdomains":5,"num_of_trigrams":20,"longest_human_readable_substring":3,"ip_blocklist_bgp":11,"ip_blocklist_asn":0,"ip_blocklist_past_ips":0,"distinct_bgp_prefixes":2,"distinct_bgp_countries":1,"distinct_bgp_orgs":1,"distinct_asns":1,"num_ip_reg_dates_fqdn":3,"num_registries_fqdn":3,"num_ip_reg_dates_3ld":3,"num_registries_3ld":3,"num_ip_reg_dates_2ld":3,"num_registries_2ld":3,"distinct_ips_3ld_zone":125,"distinct_prefixes_3ld_zone":9,"distinct_bgp_countries_3ld_zone":1,"distinct_as_names_3ld_zone":1,"distinct_asn_3ld_zone":4,"distinct_ips_2ld_zone":23501,"distinct_prefixes_2ld_zone":621,"distinct_bgp_countries_2ld_zone":2,"distinct_as_names_2ld_zone":5,"distinct_asn_2ld_zone":23,"rhdn_count":30,"rhdn_length_median":28.0,"rhdn_length_mean":28.333333333333332,"rhdn_length_std":5.569759619788113,"rhdn_1gram_mean":26.5625,"rhdn_2gram_mean":4.712643678160919,"rhdn_3gram_mean":3.1983805668016196,"rhdn_1gram_median":18.0,"rhdn_2gram_median":2.0,"rhdn_3gram_median":2.0,"rhdn_1gram_std":26.565882137621553,"rhdn_2gram_std":4.933833570421783,"rhdn_3gram_std":3.365266352066519,"stddev_tld_freq":2.1213203435596424,"avg_tld_freq":0.5,"median_tld_freq":0.5,"distinct_tld_count":2,"com_other_ratio":1.5}
        self.graph = Graph()
       
        with open(self.infra_config["datasets"]["as_radix"], "rb") as f: 
            self.as_radix = pickle.load(f)
        with open(self.plan_config["historical_dns"]["rhips_path"]) as f: 
            rhip_list = json.load(f)
        # rhip_list is a dictionary. key is domain, value is list of IPs
        self.rhip_list = {}
        for domain, ips in rhip_list.items():
            self.rhip_list[domain] = list(map(lambda x: self.parse_ip(x), ips))

        with open(self.plan_config["historical_dns"]["rhips_path_2ld"]) as f:
            rhip_2ld_list = json.load(f)
        rhip_2ld_list_ip_obj = {}
        for domain, ips in rhip_2ld_list.items():
            rhip_2ld_list_ip_obj[domain] = list(map(lambda x: self.parse_ip(x), ips))

        with open(self.plan_config["historical_dns"]["rhips_path_3ld"]) as f: 
            rhip_3ld_list = json.load(f)
            rhip_3ld_list_ip_obj = {}
            for domain, ips in rhip_3ld_list.items():
                rhip_3ld_list_ip_obj[domain] = list(map(lambda x: self.parse_ip(x), ips))

        with open(self.plan_config["historical_dns"]["subdomains_path"]) as f:
            subdomain_count = json.load(f)

        domain = Domain("12s3.lvlt.hls.eu.aiv-cdn.net")
        domain.rhips = self.rhip_list[domain.name]
        ip_blocklist_as_file = open(self.infra_config["datasets"]["ip_blocklist_as"])
        ip_blocklist_bgp_file = open(self.infra_config["datasets"]["ip_blocklist_prefix"])
        rhdn_file = open(self.plan_config["historical_dns"]["rhdns_path"])
        extractor = FeatureExtraction(
            datetime.strptime(self.plan_config["date"], "%Y-%m-%d"),
            rhip_list=rhip_list,
            ip_blocklist_as=json.load(ip_blocklist_as_file),
            ip_blocklist_prefix=json.load(ip_blocklist_bgp_file),
            rhdn_list=json.load(rhdn_file),
            rhip_2ld_list=rhip_2ld_list_ip_obj,
            rhip_3ld_list=rhip_3ld_list_ip_obj,
            subdomain_list=subdomain_count,
            popularity_list={domain_name: int(rank) for rank, domain_name in (s.rstrip().split(",") for s in open(self.infra_config["datasets"]["popularity_list"]))},
            wordlist=[s.rstrip() for s in open(self.infra_config["datasets"]["wordlist"])]
        )
        
        ip_blocklist_as_file.close()
        ip_blocklist_bgp_file.close()
        rhdn_file.close()
        
        new_vector = extractor.get_feature_vector(domain)

        print("== DIFFERENCES ==")
        missing = []
        for key in feature_vector.keys():
            if key not in new_vector.keys():
                missing.append(key)
                continue
            if round(feature_vector[key], 2) != round(new_vector[key], 2):
                print(key, "actual:", feature_vector[key], "computed:", new_vector[key])
        print("Missing:", missing)
        

    def parse_domain(self, domain_name, rhips=[]):
        domain = self.graph.get_domain(domain_name)
        if domain is None:
            domain = Domain(domain_name, rhips=rhips)
            self.graph.add_domain(domain)

        domain.rhips = rhips
        return domain
    
    def parse_ip(self, ip):
        ip_obj = self.graph.get_ip(ip)
        if ip_obj is None:
            try:
                ip = int(ip)
                ip = str(ipaddress.ip_address(ip))
            except:
                pass
            ip_obj = IP(ip)
            ip_node = self.as_radix.search_best(ip)
            if ip_node is not None:
                # print(ip_node.data)
                ip_obj.asn = ip_node.data["asn"]
                ip_obj.country = ip_node.data["country"]
                # ip_obj.registration_date = ip_node.data["registration_date"]
                ip_obj.prefix = ip_node.prefix
                ip_obj.org = ip_node.data["name"] 
                ip_obj.registration_date = ip_node.data["changed"]
                ip_obj.registry = ip_node.data["registry"]
            self.graph.add_ip(ip_obj)
        return ip_obj
 


if __name__ == '__main__': 
    unittest.main()
