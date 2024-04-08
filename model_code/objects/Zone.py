class Zone():
    def __init__(self, name):
        self.name = name
        self.rhips = []

    
    def __eq__(self, item):
        return item.name == self.name
    
    def __hash__(self):
        return hash(self.name)