from service.Service import Service

class ModelService():
    def __init__(self, name):
        self.name = name

    def get_score(self, domain):
       raise NotImplementedError("get_reputation_score not implemented") 
    
