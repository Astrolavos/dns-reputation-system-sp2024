import yaml
import argparse
import json
import pickle
from datetime import datetime

from service.models.SurrogateModelService import SurrogateModelService
from service.models.ModelSelection import ModelSelection
# from service.models.AdditiveModelService import AdditiveModelService

from features.feature_extraction import FeatureExtraction

from objects.Domain import Domain
from objects.IP import IP
from objects.Graph import Graph
from objects.Zone import Zone

class Main():
    
    def __init__(self, infra_config, plan_config):
        self.infra_config = infra_config
        self.plan_config = plan_config

        # Setup configs
        local_model = self.infra_config["services"]["local_model"]

        self.graph = Graph()
        self.as_radix = pickle.load(open(self.infra_config["datasets"]["as_radix"], "rb"))

        visible_datasets = infra_config["visibility"][plan_config["visibility"]]
        
        
        with open(self.plan_config["historical_dns"]["subdomains_path"]) as f:
            subdomain_count = json.load(f)

        ips_with_ptr_records = set()

        self.feature_extraction = FeatureExtraction(
            datetime.strptime(self.plan_config["date"], "%Y-%m-%d"),
            ip_blocklist_as=json.load(open(visible_datasets["ip_blocklist_as"])),
            ip_blocklist_prefix=json.load(open(visible_datasets["ip_blocklist_prefix"])),
            subdomain_list=subdomain_count,
            popularity_list={domain_name: int(rank) for rank, domain_name in (s.rstrip().split(",") for s in open(self.infra_config["datasets"]["popularity_list"]))},
            ptr_set=ips_with_ptr_records,
            wordlist=[s.rstrip() for s in open(self.infra_config["datasets"]["wordlist"])]
        )

        model_types = {
            "local": SurrogateModelService,
            "model_selection": ModelSelection
        }
        self.local_model = model_types[self.plan_config["model_type"]](self.plan_config["model_type"], 
                                                local_model, 
                                                visible_datasets["spark_dataset"], 
                                                plan_config["visibility"], 
                                                self.feature_extraction) 

       
        rhip_2ld_list = json.load(open(self.plan_config["historical_dns"]["rhips_path_2ld"]))
        for sld, ips in rhip_2ld_list.items():
            zone = self.get_or_create_zone(sld)
            zone.rhips = list(map(lambda x: self.get_or_create_ip(x), ips))
            # print()
        rhip_3ld_list = json.load(open(self.plan_config["historical_dns"]["rhips_path_3ld"]))
        for threeld, ips in rhip_3ld_list.items():
            zone = self.get_or_create_zone(threeld)
            zone.rhips = list(map(lambda x: self.get_or_create_ip(x), ips))       

        # Load RHDN relationships into graph
        self.rhdns = json.load(open(self.plan_config["historical_dns"]["rhdns_path"]))
        for ip_str, rhdn_list in self.rhdns.items():
            ip = self.get_or_create_ip(ip_str)
            for rhdn in rhdn_list:
                domain = self.get_or_create_domain(rhdn)
                if ip not in domain.rhips:
                    domain.rhips.append(ip)
                ip.rhdns.append(domain)

        # Load RHIP relationships into graph
        self.rhips = json.load(open(self.plan_config["historical_dns"]["rhips_path"]))
        for domain_name, rhips in self.rhips.items():
            ip_set = set()
            for ip_str in rhips:
                ip = self.get_or_create_ip(ip_str)
                ip_set.add(ip)
                
            domain = self.get_or_create_domain(domain_name)
            rhip_set = set(domain.rhips)
            for ip in ip_set:
                if ip not in rhip_set:
                    domain.rhips.append(ip)
                if domain not in ip.rhdns:
                    ip.rhdns.append(domain)
            # print("Added " + str(len(ip_set)) + " rhips to " + domain.name)
        
    def get_or_create_domain(self, domain_name):
        domain = self.graph.get_domain(domain_name)
        if domain is None:
            domain = Domain(domain_name)
            sld = domain.get_2ld()
            domain.popularity_rank = self.feature_extraction.popularity_list[sld] if sld in self.feature_extraction.popularity_list else 999999999
            domain.creation_date = self.feature_extraction.creation_dates[domain_name] if domain_name in self.feature_extraction.creation_dates else None
            domain.expiration_date = self.feature_extraction.expiration_dates[domain_name] if domain_name in self.feature_extraction.expiration_dates else None
            self.graph.add_domain(domain)
        return domain

    def get_or_create_ip(self, ip_address):
        ip = self.graph.get_ip(ip_address)
        if ip is None:
            ip = IP.parse_ip(ip_address, self.as_radix)

            if ip.ip in self.feature_extraction.ptr_set:
                ip.has_ptr = True
            self.graph.add_ip(ip)
        return ip
    
    def get_or_create_zone(self, zone_name):
        zone = self.graph.get_zone(zone_name)
        if zone is None:
            zone = Zone(zone_name)
            self.graph.add_zone(zone)
        return zone
 
   
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--infra', type=str, help='Infra config file')
    args = parser.parse_args()
    
    infra_config = yaml.load(open(args.infra, "r"), Loader=yaml.FullLoader)
    plan_config = yaml.load(open(args.plan, "r"), Loader=yaml.FullLoader)

    main = Main(infra_config, plan_config)