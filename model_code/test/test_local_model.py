import unittest
from service.models.LocalModelService import LocalModelService
import yaml
import os

class TestLocalModel(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        config_path = os.environ["CONFIG_PATH"]
        with open(config_path) as f:
            cls.config = yaml.load(f, Loader=yaml.FullLoader)

 
    def test_local_model_get(self):
        local_model_config = self.config["services"]["local_model"] 
        local_model = LocalModelService("local", local_model_config["path"], local_model_config["ground_truth_path"])
        print(local_model.get_score("development--cgi--cfit--projekt892-intranet--simpplr--c.visualforce.com"))
        assert(local_model.get_score("development--cgi--cfit--projekt892-intranet--simpplr--c.visualforce.com") is not None)
     


if __name__ == '__main__': 
    unittest.main()
