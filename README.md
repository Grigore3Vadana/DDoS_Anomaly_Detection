### DETECTION OF DOS/DDOS ATTACKS AT THE  APPLICATION LEVEL THROUGH MACHINE LEARNING: COMPARATIVE  ANALYSIS OF ANOMALY DETECTION ALGORITHMS' PERFORMANCE

---

### Description

This project analyzes the automatic detection of application layer DoS/DDoS attacks using unsupervised anomaly detection algorithms on the CIC-IDS-2017 dataset and various preprocessing and feature engineering techniques.

The study evaluates the performance of several algorithms (KNN, Isolation Forest, LOF, HBOS, CBLOF) in diverse training scenarios combined with derived metrics or subsets specific to a particular type of attack. The obtained results demonstrate the advantages or disadvantages of specific approaches in detecting application layer DoS/DDoS attacks.

### Main objectives:

* Identifying the relevant features of network traffic for the automatic detection of DoS/DDoS attacks at the application level.

* Comparative analysis of the performance of anomaly detection algorithms in identifying DoS/DDoS attacks, both at a general level and at the application level.

#### Dataset: CIC-IDS-2017 
* The file selected from the website [[1]] to be used as the database is "Wednesday-workingHours.pcap_ISCX.csv (225.17 MB)". It was specifically chosen due to its traffic distribution (including BENIGN traffic) and presence of DDoS attacks (details can be found in the 'dataset' directory).

[1]: https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset

---
#### The file responsible for data analysis: analiza_dataset.py

---


The project itself represents a pipeline (**ddos.py**) dedicated to the detection of DoS/DDoS attacks at the application level using anomaly detection algorithms. This pipeline allows the selection of the desired experimental scenario in order to be evaluated through comparative analysis.


### How the pipeline works?
Steps:
1. Run **ddos.py** 

---
#### ddos.py - the main file, since it orchestrates the entire pipeline

---

2. Select the desired options that appear in the execution window:
---

Output:

=== Filter Menu Train ===
  1) Only benign (Label_str='BENIGN')
  2) Benign + user typed attacks (e.g., 'DoS Hulk,DDoS')
  3) No filtering (take all train)
  0) Total exit
Filter choice: x

=== Preprocessing Menu ===
  1) No transform, no scaling
  2) Transform, no scaling
  3) Transform + StandardScaler
  4) Transform + MinMaxScaler
  5) Transform + RobustScaler
  0) Back to filter menu
Preprocessing choice: x

=== Model Menu (pyod) ===
  1) IForest
  2) OCSVM
  3) LOF
  4) KNN
  5) HBOS
  6) CBLOF
  0) Back to preprocessing menu
Model choice: x

=== Feature Engineering Menu ===
  1) NoFE – No Results - feature engineering (preprocessed set)
  2) EngOnly – Only derived metrics
  3) Aug – Original set + derived metrics
  4) AppSpec – Only application-specific features
  5) AppSpec+Comb – Specific + derived
  6) HTTPFlood – Flow Packets/s, Flow Bytes/s, FwdBwdPacketRatio, PacketLengthRange
  7) SlowHTTP – Flow Duration, Idle Mean, IdleActiveImbalance, PacketLengthRange
  8) SYNHTTPHybrid – SYN Count, Flow Packets/s, SynRate, SynBurstScore
  0) NoMod – (fallback with no modifications)
Feature engineering choice: x

---

### Results

#### Performance Metrics

At each test iteration, the result is displayed in the execution window, indicating the precision, accuracy, sensitivity, and F1-score, as well as the ROC curve and AUC area. At the end of the iterations, an average is calculated over the 10 tests for each obtained metric, which is then saved in a .xlsx file.

- For a general and quick comparative analysis, the following data can be visualized:

1. The results of the experimental scenarios without selecting feature engineering techniques (**check** Results - no feature engineering)
2. The results of the experimental scenarios where feature engineering techniques were used (**check** Results - feature engineering)
3. roc_curves_(with/no)_feature_engineering → includes the ROC curves for each scenario. In each image with the ROC curve, you can see 10 lines of different colors (they represent the tests done on that scenario)

- For those who wish to analyze in more detail, I have separated the results into categories:

1. The results divided according to the training scenario (**check** results/training scenario/*)
2. The results divided according to the selected feature engineering techniques (**check** feature engineering techniques/*)
---

### Observations to understand the results

###### The title for each table and also for each ROC curve is given according to the following format:

- For the results without feature engineering techniques

###### Filter{f}_Preproc{p}_Model{m}

- For the results with feature engineering techniques

###### Filter{f}_Preproc{p}_Model{m}_FE{t}

---
### Comparative Analysis of the Performance of Detection Algorithms in Identifying DoS/DDoS Attacks at the Application Level

 The best results were obtained in the augmentation scenario (**LOF Algorithm, Log/Yeo-Johnson transformation, MinMaxScaler()**), with all relevant metrics (F1, recall, ROC AUC) reaching optimal levels for DoS/DDoS detection.

---

#### The project (bachelor degree) was carried out within the institute:
* National University of Science and Technology Politehnica Bucharest
* Faculty of Automatic Control and Computers
* Department of Automation and Industrial Informatics

© 2024 Grigore Vadana. All rights reserved.
