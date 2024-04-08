from joblib import load
from . import ModelService
import json
import pandas as pd
# import util
import os
import sys
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, roc_auc_score, precision_score, balanced_accuracy_score, recall_score
from joblib import dump
import sys
import yaml
import tldextract
from imblearn.under_sampling import RandomUnderSampler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from xgboost import XGBClassifier


class ModelSelection():

    def __init__(self, name, local_model_config, spark_data_location, visibility, feature_extractor, subset=None):
        self.name = name
        self.model_config = local_model_config
        self.feature_extractor = feature_extractor
        self.visibility = visibility
        self.spark_data_location = spark_data_location
        self.subset = subset
        
        
        if not os.path.exists(os.path.join(self.model_config["model_folder"], self.visibility)):
            os.makedirs(os.path.join(self.model_config["model_folder"], self.visibility))
        if not os.path.exists(os.path.join(self.model_config["ground_truth_folder"], self.visibility)):
            os.makedirs(os.path.join(self.model_config["ground_truth_folder"], self.visibility))
        self.model_path = os.path.join(self.model_config["model_folder"], self.visibility, "model.joblib")
        # if os.path.exists(self.model_path):
            # print(self.model_path)
            # self.clf = load(self.model_path)
        # else:
        self.train()

    def get_score(self, domain):
        feature_vector = pd.DataFrame(self.feature_extractor.get_feature_vector(domain), index=[0]).sort_index(axis=1).fillna(0)
        # print(feature_vector.columns)
        # print(feature_vector.to_csv())
        # remove columns not in subs
        if self.subset is not None:
            feature_vector = feature_vector[self.subset]
        if feature_vector is not None: 
            return self.__predict__(feature_vector)[0][0]
        else:
            return None
   
    def get_test_stats(self):
        return json.loads(open(os.path.join(self.model_config["model_folder"], self.visibility, "performance.json"), "r").read())


    def train(self):
        FOLDS = 2

        extract = tldextract.TLDExtract(include_psl_private_domains=True)
        
        df = (pd.read_parquet(self.spark_data_location)
                .fillna(0))
        df = df.reindex(sorted(df.columns), axis=1)
        df["2ld"] = df["qname"].apply(lambda x: ".".join(extract(x)[-2:]))
        df = df[(df.groupby(['2ld']).cumcount() <= 10) | (df["qname"] == df["2ld"])]
        
        if self.subset is not None:
            df = df[self.subset + ["malicious", "qname", "2ld", *("type" if "type" in df.columns else [])]]
        
        train, test = self.stratified_group_train_test_split(df, "2ld", "malicious", 0.1)
        
        train = train.drop(columns=["qname", "2ld", *("type" if "type" in train.columns else [])])
        test = test.drop(columns=["qname", "2ld", *("type" if "type" in test.columns else [])])

        ros = RandomUnderSampler(random_state=42)
        X_train, y_train = ros.fit_resample(pd.DataFrame(train.drop(columns=["malicious"])), pd.DataFrame(train["malicious"]))

        param_grid_rf = {
            'max_depth': [10],
            'n_estimators': [100],
            'criterion': ["gini"] #, "entropy"]
        }

        param_grid_svc = {
            'C': [0.1, 1, 10],
            'gamma': [1, 0.1, 0.01],
            'kernel': ['rbf', 'linear']
        }

        param_grid_knn = {
            'n_neighbors': [3],
            'weights': ['uniform'] # , 'distance']
        }

        param_grid_log_reg = {
            'C': [0.1],
            'solver': ['liblinear'] # , 'lbfgs']
        }

        param_grid_xgb = {
            'max_depth': [3, 6, 9],
            'n_estimators': [50, 100, 150],
            'learning_rate': [0.1, 0.01, 0.001]
        }


        classifiers = [
            (RandomForestClassifier(), param_grid_rf),
            # (SVC(), param_grid_svc),
            (KNeighborsClassifier(), param_grid_knn),
            (LogisticRegression(), param_grid_log_reg),
            (XGBClassifier(), param_grid_xgb)
        ]
        best_scores = np.zeros((6 + 4))

        for clf, param_grid in classifiers:
            grid_search = GridSearchCV(clf, param_grid, cv=FOLDS, scoring='accuracy')
            grid_search.fit(X_train, y_train)

            best_params = grid_search.best_params_
            self.clf = grid_search.best_estimator_
            
            dump(self.clf, self.model_path + "-{}".format(clf.__class__.__name__))
            
            # df.drop(columns=["2ld"], inplace=True)
            # with open(os.path.join(self.model_config["model_folder"], self.visibility, "test.json"), 'w+') as f:
            #     for i in range(len(test)):
            #         record = test.iloc[i].to_json()
            #         f.write(record + "\n")
            # with open(os.path.join(self.model_config["model_folder"], self.visibility, "train.json"), 'w+') as f:
            #     for i in range(len(train)):
            #         record = train.iloc[i].to_json()
            #         f.write(record + "\n")
            
            test_X = test.drop(columns="malicious")#.drop(columns=["qname", "2ld", "malicious", *("type" if "type" in test.columns else [])])
            y_test = test["malicious"]
            y_pred = self.clf.predict(test_X)
            # print(f"Best depth {self.clf.max_depth}, best n_estimators {self.clf.n_estimators}, best criterion: {self.clf.criterion}")
            best_scores[0] = accuracy_score(y_test, y_pred)
            best_scores[1] = balanced_accuracy_score(y_test, y_pred)
            best_scores[2] = f1_score(y_test, y_pred)
            best_scores[3] = precision_score(y_test, y_pred)
            best_scores[4] = recall_score(y_test, y_pred)
            best_scores[5] = roc_auc_score(y_test, y_pred)
            best_scores[6:10] = confusion_matrix(y_test, y_pred, normalize="true").flatten()
            print("Finished training model!")
            print("Test set performance:")
            performance_metrics = {
                "classifier": str(self.clf),
                "accuracy": best_scores[0],
                "balanced_accuracy": best_scores[1],
                "f1": best_scores[2],
                "precision": best_scores[3],
                "recall": best_scores[4],
                "auc": best_scores[5],
                "tnr": best_scores[6],
                "fpr": best_scores[7],
                "fnr": best_scores[8],
                "tpr": best_scores[9]
            }
            open(os.path.join(self.model_config["model_folder"], self.visibility, "performance.json"), "a+").write(json.dumps(performance_metrics) + "\n")
            print("Accuracy: {:.3f}, Balanced accuracy: {:.3f}, F1: {:.3f}, Precision: {:.3f}, Recall: {:.3f}, AUC: {:.3f}, TN: {:.3f}, FP: {:.3f}, FN: {:.3f}, TP: {:.3f}".format(*best_scores[0:10]))

    
    def __predict__(self, feature_vectors):
        y_pred = self.clf.predict_proba(feature_vectors)
        return y_pred

    def update(self, domain):
        pass

    def stratified_group_train_test_split(self, samples: pd.DataFrame, group: str, stratify_by: str, test_size: float):
        groups = samples[group].drop_duplicates()
        stratify = samples.drop_duplicates(group)[stratify_by].to_numpy()
        groups_train, groups_test = train_test_split(groups, stratify=stratify, test_size=test_size, random_state=42)

        samples_train = samples.loc[lambda d: d[group].isin(groups_train)]
        samples_test = samples.loc[lambda d: d[group].isin(groups_test)]

        return samples_train, samples_test

