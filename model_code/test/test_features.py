import unittest
from service.models.LocalModelService import LocalModelService
import yaml
import os
import json
from objects.Domain import Domain
import numpy as np
import math
from sklearn.feature_extraction.text import CountVectorizer
import tldextract
import pickle
import radix

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

 
    def lexical_features(self, domain):
        vector = {}
        vector["domain_length"] = len(domain) - len(self.extract(domain).suffix) - 1
       
        vector["number_ratio"] = 0
        for char in domain[:-len(self.extract(domain).suffix)-1]:
            if char.isdigit():
                vector["number_ratio"] += 1
        vector["number_ratio"] /= len(domain)
        return vector


    def network_features(self, domain):
        vector = {}
        
        rhips_of_d = self.rhips[domain]
        
        vector["distinct_ips"] = len(rhips_of_d)
        vector["distinct_asns"] = len(self.asns)
        vector["distinct_bgp_countries"] = len(self.countries)
        vector["distinct_bgp_prefixes"] = len(self.prefixes)
        
        def getThirdLD(tld):
            if tld is None:
                return ""
            extracted = self.extract(tld)
            if len(extracted[0].split('.')) == 0: return ''
            return extracted[0].split('.')[-1] + '.' + '.'.join(extracted[-2:])

        def getSecondLD(tld):
            if tld is None:
                return ""
            extracted = self.extract(tld)
            return '.'.join(extracted[-2:])

        asns_2ld = set()
        prefixes_2ld = set()
        countries_2ld = set()
        orgs_2ld = set() 
        sld = getSecondLD(domain)
        for rhip in self.rhips_2ld[sld]:
            node = self.rtree.search_best(rhip) 
            if node is None:
                print("error:", rhip)
                continue
            asns_2ld.add(int(node.data["asn"]))
            prefixes_2ld.add(node.prefix)
            if node.data["country"] != "-":
                countries_2ld.add(node.data["country"])
            if node.data["name"] != "-":
                orgs_2ld.add(node.data["name"])

        # print(set(rhips_2ld[sld]))
        vector["distinct_ips_2ld_zone"] = len(set(self.rhips_2ld[sld]))
        vector["distinct_asn_2ld_zone"] = len(asns_2ld)
        vector["distinct_bgp_countries_2ld_zone"] = len(countries_2ld)
        vector["distinct_prefixes_2ld_zone"] = len(prefixes_2ld)
        
       
        asns_3ld = set()
        prefixes_3ld = set()
        countries_3ld = set()
        # orgs = set() 
        threeld = getThirdLD(domain)
        
        asns_3ld = set()
        prefixes_3ld = set()
        countries_3ld = set()
        orgs_3ld = set() 
        for rhip in self.rhips_3ld[threeld]:
            node = self.rtree.search_best(rhip) 
            if node is None:
                print("error:", rhip)
                continue
            asns_3ld.add(int(node.data["asn"]))
            prefixes_3ld.add(node.prefix)
            if node.data["country"] != "-":
                countries_3ld.add(node.data["country"])
            if node.data["name"] != "-":
                orgs_3ld.add(node.data["name"])
        
        vector["distinct_ips_3ld_zone"] = len(self.rhips_3ld[threeld])
        vector["distinct_asn_3ld_zone"] = len(asns_3ld)
        vector["distinct_bgp_countries_3ld_zone"] = len(countries_3ld)
        vector["distinct_prefixes_3ld_zone"] = len(prefixes_3ld)
        return vector

    def evidence_features(self, domain):
        vector = {}
        rhips_of_d = self.rhips[domain]
        
        # Evidence
        as_to_ips = json.load(open(self.infra_config["datasets"]["ip_blocklist_as"]))
        bgp_to_ips = json.load(open(self.infra_config["datasets"]["ip_blocklist_prefix"]))
        vector["ip_blocklist_asn"] = 0
        vector["ip_blocklist_bgp"] = 0
        vector["ip_blocklist_past_ips"] = 0
        
        malware_ips_set = set([item for sublist in as_to_ips for item in sublist])
        
        for asn in self.asns:
            if str(asn) in as_to_ips:
                vector["ip_blocklist_asn"] += len(as_to_ips[str(asn)])
        for prefix in self.prefixes:
            print(prefix)
            if prefix in bgp_to_ips:
                vector["ip_blocklist_bgp"] += len(bgp_to_ips[prefix]) 
                
        for ip in rhips_of_d:
            if ip in malware_ips_set:
                vector["ip_blocklist_past_ips"] += 1

        return vector
               
 
    def rhdns_features(self, domain):
        vector = {}

        rhdns_of_d = []
        
        for rhip in self.rhips_of_d:
            rhdns_of_d.extend(self.rhdns[rhip])
        
        rhdns_of_d = list(set(rhdns_of_d))


        lengths = [len(rhdn) for rhdn in rhdns_of_d]
        # print(rhdns_of_d)
        vector["rhdn_count"] = len(rhdns_of_d)
        vector["rhdn_length_mean"] = np.mean(lengths)
        vector["rhdn_length_median"] = np.median(lengths)
        vector["rhdn_length_std"] = float(np.std(lengths))
        
        one_grams = CountVectorizer(ngram_range=(1,1), analyzer='char').fit_transform(rhdns_of_d).toarray().sum(axis=0)
        two_grams = CountVectorizer(ngram_range=(2,2), analyzer='char').fit_transform(rhdns_of_d).toarray().sum(axis=0)
        three_grams = CountVectorizer(ngram_range=(3,3), analyzer='char').fit_transform(rhdns_of_d).toarray().sum(axis=0)

        def getName(domain):
            extracted = self.extract(domain)
            str = ".".join(extracted[0:2])
            if str[0] == ".":
                return str[1:]
            return str

        vector["num_of_trigrams"] = np.size(CountVectorizer(ngram_range=(3,3), analyzer='char').fit_transform([getName(domain)]).toarray().sum(axis=0))
        vector["num_of_bigrams"] = np.size(CountVectorizer(ngram_range=(2,2), analyzer='char').fit_transform([getName(domain)]).toarray().sum(axis=0))
        
        
        vector["rhdn_1gram_mean"] = float(np.mean(one_grams))
        vector["rhdn_2gram_mean"] = float(np.mean(two_grams))
        vector["rhdn_3gram_mean"] = float(np.mean(three_grams))
        vector["rhdn_1gram_median"] = float(np.median(one_grams))
        vector["rhdn_2gram_median"] = float(np.median(two_grams))
        vector["rhdn_3gram_median"] = float(np.median(three_grams))
        vector["rhdn_1gram_std"] = float(np.std(one_grams))
        vector["rhdn_2gram_std"] = float(np.std(two_grams))
        vector["rhdn_3gram_std"] = float(np.std(three_grams))
        

        tld_counts = {}
        for rhdn in rhdns_of_d:
            tld = self.extract(rhdn).suffix
            if tld not in tld_counts:
                tld_counts[tld] = 0
            tld_counts[tld] += 1
        
        vector["distinct_tld_count"] = len(tld_counts.keys())
        vector["avg_tld_freq"] = np.mean(list(tld_counts.values())) / len(rhdns_of_d)
        vector["stddev_tld_freq"] = np.std(list(tld_counts.values())) / len(rhdns_of_d)
        vector["median_tld_freq"] = np.median(list(tld_counts.values())) / len(rhdns_of_d)
        
        if "com" in tld_counts:
            vector["com_other_ratio"] = tld_counts["com"] / (sum(v for k, v in tld_counts.items() if k != "com"))
        else:
            vector["com_other_ratio"] = 0

        return vector

 
    def test_features(self):
        feature_vector = {
        "qname": "12s3.lvlt.hls.eu.aiv-cdn.net",
        "malicious": False,
        "ct_valid_length": 29894399,
        "days_created_expires": 2557,
        "days_created_now": 2322,
        "pop_1m_null": 0,
        "pop_1m_rising": 0,
        "pop_1m_falling": 0,
        "pop_1m_stable": 1,
        "pop_100k_null": 0,
        "pop_100k_rising": 0,
        "pop_100k_falling": 0,
        "pop_100k_stable": 1,
        "pop_10k_null": 0,
        "pop_10k_rising": 0,
        "pop_10k_falling": 0,
        "pop_10k_stable": 1,
        "pop_1k_null": 1,
        "pop_1k_rising": 0,
        "pop_1k_falling": 0,
        "pop_1k_stable": 0,
        "distinct_ips": 3,
        "rdns_ratio": 0.0,
        "number_ratio": 0.125,
        "domain_length": 24,
        "num_of_subdomains": 5,
        "num_of_trigrams": 20,
        "longest_human_readable_substring": 3,
        "ip_blocklist_bgp": 70,
        "ip_blocklist_asn": 0,
        "ip_blocklist_past_ips": 0,
        "distinct_bgp_prefixes": 2,
        "distinct_bgp_countries": 1,
        "distinct_bgp_orgs": 1,
        "distinct_asns": 1,
        "num_ip_reg_dates_fqdn": 3,
        "num_registries_fqdn": 3,
        "num_ip_reg_dates_3ld": 3,
        "num_registries_3ld": 3,
        "num_ip_reg_dates_2ld": 3,
        "num_registries_2ld": 3,
        "distinct_ips_3ld_zone": 125,
        "distinct_prefixes_3ld_zone": 10,
        "distinct_bgp_countries_3ld_zone": 2,
        "distinct_asn_3ld_zone": 4,
        "distinct_ips_2ld_zone": 12292,
        "distinct_prefixes_2ld_zone": 397,
        "distinct_bgp_countries_2ld_zone": 4,
        "distinct_asn_2ld_zone": 24,
        "rhdn_count": 30,
        "rhdn_length_median": 28.0,
        "rhdn_length_mean": 28.333333333333332,
        "rhdn_length_std": 5.569759619788114,
        "rhdn_1gram_mean": 26.5625,
        "rhdn_2gram_mean": 4.712643678160919,
        "rhdn_3gram_mean": 3.1983805668016196,
        "rhdn_1gram_median": 18.0,
        "rhdn_2gram_median": 2.0,
        "rhdn_3gram_median": 2.0,
        "rhdn_1gram_std": 26.565882137621553,
        "rhdn_2gram_std": 4.933833570421783,
        "rhdn_3gram_std": 3.365266352066519,
        "stddev_tld_freq": 2.1213203435596424,
        "avg_tld_freq": 0.5,
        "median_tld_freq": 0.5,
        "distinct_tld_count": 2,
        "com_other_ratio": 1.5
        }


        domain = "12s3.lvlt.hls.eu.aiv-cdn.net"
        self.extract = tldextract.TLDExtract(include_psl_private_domains=True)


        self.rtree = pickle.load(open(self.infra_config["datasets"]["as_radix"], "rb"))

        self.asns = set()
        self.prefixes = set()
        self.countries = set()
        self.orgs = set()
            

        self.rhdns = json.load(open(self.plan_config["historical_dns"]["rhdns_path"], "r"))
        
        self.rhips_2ld = json.load(open(self.plan_config["historical_dns"]["rhips_path_2ld"], "r"))
        self.rhips_3ld = json.load(open(self.plan_config["historical_dns"]["rhips_path_3ld"], "r"))
        
        self.rhips = json.load(open(self.plan_config["historical_dns"]["rhips_path"], "r"))

        self.rhips_of_d = self.rhips[domain]
        
        for rhip in self.rhips_of_d:
            node = self.rtree.search_best(rhip) 
            if node is None:
                continue
            self.asns.add(int(node.data["asn"]))
            self.prefixes.add(node.prefix)
            if node.data["country"] != "-":
                self.countries.add(node.data["country"])
            if node.data["name"] != "-":
                self.orgs.add(node.data["name"])


        new_vector = {}


        new_vector.update(self.lexical_features(domain))
        new_vector.update(self.network_features(domain))
        new_vector.update(self.evidence_features(domain))
        new_vector.update(self.rhdns_features(domain))
    


        print("== DIFFERENCES ==")
        missing = []
        for key in feature_vector.keys():
            if key not in new_vector.keys():
                missing.append(key)
                continue
            if round(feature_vector[key], 2) != round(new_vector[key], 2):
                print(key, "actual:", feature_vector[key], "computed:", new_vector[key])
        print("Missing:", missing)
        



if __name__ == '__main__': 
    unittest.main()
