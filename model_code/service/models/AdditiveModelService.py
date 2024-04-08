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
from sklearn.model_selection import StratifiedGroupKFold, cross_val_score, cross_val_predict, train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, roc_auc_score, precision_score, balanced_accuracy_score, recall_score
from joblib import dump
import sys
from sklearn.decomposition import PCA
from sklearn.preprocessing import Normalizer
import yaml
import tldextract
from imblearn.under_sampling import RandomUnderSampler
from sklearn.model_selection import GroupShuffleSplit

class AdditiveModelService():

    def __init__(self, name, local_model_config, spark_data_location, visibility, feature_extractor, feature_classes):
        self.name = name
        self.model_config = local_model_config
        self.feature_extractor = feature_extractor
        self.visibility = visibility
        self.spark_data_location = spark_data_location
        self.feature_classes = feature_classes
        
        if not os.path.exists(os.path.join(self.model_config["model_folder"], self.visibility)):
            os.makedirs(os.path.join(self.model_config["model_folder"], self.visibility))
        if not os.path.exists(os.path.join(self.model_config["ground_truth_folder"], self.visibility)):
            os.makedirs(os.path.join(self.model_config["ground_truth_folder"], self.visibility))
        
        self.clfs = {}
        for class_name in self.feature_classes.keys():
            self.model_path = os.path.join(self.model_config["model_folder"], self.visibility, class_name + ".joblib")
            if os.path.exists(self.model_path):
                self.clfs[class_name] = load(self.model_path)
            else:
                self.clfs[class_name] = self.train_method(class_name, self.model_path)
        # cleanup training process
        self.df = None
        self.train = None
        self.test = None
        self.X_train = None
        self.y_train = None
        self.X_train_resampled = None
        self.y_train_resampled = None

    def get_score(self, domain):
        score = 0
        feature_vector = pd.DataFrame(self.feature_extractor.get_feature_vector(domain), index=[0]).sort_index(axis=1).fillna(0)
        for class_name, features in self.feature_classes.items():
            feature_vector = feature_vector[features]
            score += self.__predict__(feature_vector)[0][0]
            
        return score / len(self.feature_classes)
    
    def get_score(self, domain, class_name):
        feature_vector = pd.DataFrame(self.feature_extractor.get_feature_vector(domain), index=[0]).sort_index(axis=1).fillna(0)
        feature_vector = feature_vector[self.feature_classes[class_name]]
        return self.__predict__(feature_vector, self.clfs[class_name])[0][0]
            

    def train_method(self, class_name, model_path):

        DEPTHS = [10]
        ESTIMATORS = [100]
        CRITERIAS = ["gini", "entropy"]
        FOLDS = 10

        extract = tldextract.TLDExtract(include_psl_private_domains=True)
        
        if not hasattr(self, "df"):
            self.df = (pd.read_parquet(self.spark_data_location)
                    .fillna(0))
            self.df = self.df.reindex(sorted(self.df.columns), axis=1)
            self.df["2ld"] = self.df["qname"].apply(lambda x: ".".join(extract(x)[-2:]))
            self.df = self.df[(self.df.groupby(['2ld']).cumcount() <= 10) | (self.df["qname"] == self.df["2ld"])]
        
            train, test = self.stratified_group_train_test_split(self.df, "2ld", "malicious", 0.1)
            self.train = train
            self.test = test
            ros = RandomUnderSampler(random_state=42)
            self.X_train, self.y_train = ros.fit_resample(pd.DataFrame(self.train.drop(columns=["malicious"])), pd.DataFrame(self.train["malicious"]))

        best_params = (0, 0, "entropy")
        kf = StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=42) 
        best_scores = np.zeros((6 + 4))

        print(f"Training '{self.visibility}.{class_name}' model {len(self.train)} training samples, {len(self.test)} testing samples")

        best_score = 1
        # print(self.X_train)
        # print(self.feature_classes[class_name])
        cols = self.feature_classes[class_name].copy()
        cols.extend(["qname", "2ld"])
        print(cols)
        X_train_subset = self.X_train[cols]
        
        for CRITERIA in CRITERIAS:
            for DEPTH in DEPTHS:
                for ESTIMATOR in ESTIMATORS:
                    clf = RandomForestClassifier(max_depth=DEPTH, criterion=CRITERIA, n_estimators=ESTIMATOR, random_state=42)
                    fold = 0
                    kfold_scores = np.zeros((FOLDS, 4))
                    for train_index, test_index in kf.split(X_train_subset, self.y_train, X_train_subset["2ld"]):
                        X_kf_train, X_kf_test = X_train_subset.iloc[train_index, :], X_train_subset.iloc[test_index, :]
                        y_kf_train, y_kf_test = self.y_train.iloc[train_index].values.ravel(), self.y_train.iloc[test_index].values.ravel()
                        
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
        clf = RandomForestClassifier(max_depth=best_depth, n_estimators=best_estimator, criterion=best_criterion)

        if not hasattr(self, "X_train_resampled"):
            X_train_final = self.train.drop(columns=["malicious", "qname", "2ld", *("type" if "type" in self.train.columns else [])])
            y_train_final = self.train["malicious"]
            self.X_train_resampled, self.y_train_resampled = ros.fit_resample(X_train_final, y_train_final)
        X_train_resampled_subset = self.X_train_resampled[self.feature_classes[class_name]]
        clf.fit(X_train_resampled_subset, self.y_train_resampled)

        # Output
        dump(clf, model_path)
        
        
        # self.df.drop(columns=["2ld"], inplace=True)
        with open(os.path.join(self.model_config["ground_truth_folder"], self.visibility, f"test.{class_name}.json"), 'w+') as f:
            for i in range(len(self.test)):
                record = self.test.iloc[i].to_json()
                f.write(record + "\n")
        with open(os.path.join(self.model_config["ground_truth_folder"], self.visibility, f"train.{class_name}.json"), 'w+') as f:
            for i in range(len(self.train)):
                record = self.train.iloc[i].to_json()
                f.write(record + "\n")
        
        test_X = self.test.drop(columns=["qname", "2ld", "malicious", *("type" if "type" in self.test.columns else [])])
        y_test = self.test["malicious"]
        y_pred = clf.predict(test_X)
        print(f"Best depth {clf.max_depth}, best n_estimators {clf.n_estimators}, best criterion: {clf.criterion}")
        best_scores[0] = accuracy_score(y_test, y_pred)
        best_scores[1] = balanced_accuracy_score(y_test, y_pred)
        best_scores[2] = f1_score(y_test, y_pred)
        best_scores[3] = precision_score(y_test, y_pred)
        best_scores[4] = recall_score(y_test, y_pred)
        best_scores[5] = roc_auc_score(y_test, y_pred)
        best_scores[6:10] = confusion_matrix(y_test, y_pred, normalize="true").flatten()
        print("Finished training model!")
        print("Test set performance:")
        print("Accuracy: {:.3f}, Balanced accuracy: {:.3f}, F1: {:.3f}, Precision: {:.3f}, Recall: {:.3f}, AUC: {:.3f}, TN: {:.3f}, FP: {:.3f}, FN: {:.3f}, TP: {:.3f}".format(*best_scores[0:10]))
        
        self.clfs[class_name] = clf
    
    def __predict__(self, feature_vectors, class_name):
        y_pred = self.clfs[class_name].predict_proba(feature_vectors)
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
