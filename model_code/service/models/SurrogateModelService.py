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
from imblearn.over_sampling import RandomOverSampler

class SurrogateModelService():

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
        if os.path.exists(self.model_path):
            print(self.model_path)
            self.clf = load(self.model_path)
        else:
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

        DEPTHS = [10]
        ESTIMATORS = [100]
        CRITERIAS = ["gini"] # , "entropy"]
        FOLDS = 10

        extract = tldextract.TLDExtract(include_psl_private_domains=True)
        
        df = (pd.read_parquet(self.spark_data_location)
                .fillna(0))
        df = df.reindex(sorted(df.columns), axis=1)
        df["2ld"] = df["qname"].apply(lambda x: ".".join(extract(x)[-2:]))
        df = df[(df.groupby(['2ld']).cumcount() <= 5) | (df["qname"] == df["2ld"])]
        
        if self.subset is not None:
            df = df[self.subset + ["malicious", "qname", "2ld", *("type" if "type" in df.columns else [])]]
        
        train, test = self.stratified_group_train_test_split(df, "2ld", "malicious", 0.1)

        ros = RandomOverSampler(random_state=42)
        X_train, y_train = ros.fit_resample(pd.DataFrame(train.drop(columns=["malicious"])), pd.DataFrame(train["malicious"]))
        
        # print(X_train.columns)
        best_params = (0, 0, "entropy")
        kf = StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=42) 
        best_scores = np.zeros((6 + 4))

        print(f"Training '{self.visibility}' model {len(train)} training samples, {len(test)} testing samples")
        print("Training set: " + str(train["malicious"].value_counts()) + " malicious")
        print("Test set: " + str(test["malicious"].value_counts()) + " malicious")

        best_score = 1

        for CRITERIA in CRITERIAS:
            for DEPTH in DEPTHS:
                for ESTIMATOR in ESTIMATORS:
                    clf = RandomForestClassifier(max_depth=DEPTH, criterion=CRITERIA, n_estimators=ESTIMATOR, random_state=42)
                    fold = 0
                    kfold_scores = np.zeros((FOLDS, 4))
                    for train_index, test_index in kf.split(X_train, y_train, X_train["2ld"]):
                        X_kf_train, X_kf_test = X_train.iloc[train_index, :], X_train.iloc[test_index, :]
                        y_kf_train, y_kf_test = y_train.iloc[train_index].values.ravel(), y_train.iloc[test_index].values.ravel()
                        
                        X_kf_train = X_kf_train.drop(["qname", "2ld", *("type" if "type" in X_kf_train.columns else [])], axis=1)
                        clf.fit(X_kf_train, y_kf_train)
                        y_pred = clf.predict(X_kf_test.drop(["qname", "2ld", *("type" if "type" in X_kf_test.columns else [])], axis=1))
                        # tnr, fpr, fnr, tpr
                        kfold_scores[fold] = confusion_matrix(y_kf_test, y_pred, normalize="true").flatten()
                        
                        fold += 1
                    kfold_score = kfold_scores.mean(axis=0)

                    if round(kfold_score[1], 4) < round(best_score, 4): # break ties by choosing model with less complexity
                        best_score = kfold_score[1]
                        best_params = (DEPTH, ESTIMATOR, CRITERIA)

        best_depth, best_estimator, best_criterion = best_params
        self.clf = RandomForestClassifier(max_depth=best_depth, n_estimators=best_estimator, criterion=best_criterion)

        X_train = train.drop(columns=["malicious", "qname", "2ld", *("type" if "type" in train.columns else [])])
        y_train = train["malicious"]
        X_train_resampled, y_train_resampled = ros.fit_resample(X_train, y_train)
        self.clf.fit(X_train_resampled, y_train_resampled)

        # Output
        dump(self.clf, self.model_path)
        
        df.drop(columns=["2ld"], inplace=True)
        with open(os.path.join(self.model_config["model_folder"], self.visibility, "test.json"), 'w+') as f:
            for i in range(len(test)):
                record = test.iloc[i].to_json()
                f.write(record + "\n")
        with open(os.path.join(self.model_config["model_folder"], self.visibility, "train.json"), 'w+') as f:
            for i in range(len(train)):
                record = train.iloc[i].to_json()
                f.write(record + "\n")
       
         
        test_X, y_test = ros.fit_resample(test.drop(columns=["qname", "2ld", "malicious", *("type" if "type" in test.columns else [])]), test["malicious"])
        # y_test = test["malicious"]
        y_pred = self.clf.predict(test_X)
        print(f"Best depth {self.clf.max_depth}, best n_estimators {self.clf.n_estimators}, best criterion: {self.clf.criterion}")
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
        open(os.path.join(self.model_config["model_folder"], self.visibility, "performance.json"), "a+").write(json.dumps(performance_metrics))
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
