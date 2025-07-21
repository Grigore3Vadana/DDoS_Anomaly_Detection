#### test.py -> **fisierul principal** intrucat aici se automatizeaza tot procesul, respectiv testele

- se ruleaza fisierul principal **test.py**

- raport_rezultate -> contine rezultatele rularii test.py

- roc_curves/* -> cuprinde curbele roc pentru fiecare scenariu. In fiecare imagine cu curba roc se pot vedea 10 linii de culori diferite (ele reprezinta testele facute pe acel scenariu)

##### Denumirea titlului pentru fiecare tabel cat si a curbelor roc cat este data sub forma:

###### Filtrare{f}_Preproc{p}_Model{m}

- f -> (1..3)
- p -> (1..5)
- m -> (1..6)
----
Meniu Filtrare Train
  1) Doar benign (Label_str='BENIGN')
  2) Benign + user typed attacks (ex: 'DoS Hulk,DDoS')
  3) Nicio filtrare (iau train tot)
  0) Iesire totala

Meniu Preprocesare
  1) Fără transform, fără scalare
  2) Transform, fără scalare
  3) Transform + StandardScaler
  4) Transform + MinMaxScaler
  5) Transform + RobustScaler
  0) Inapoi meniu filtrare

Meniu Model (pyod)
  1) IForest
  2) OCSVM
  3) LOF
  4) KNN
  5) HBOS
  6) CBLOF
  0) Inapoi meniu preprocesare

----
distributia datelor

Label
- BENIGN              : 440031
- DoS Hulk            : 231073
- DoS GoldenEye        : 10293
- DoS slowloris         : 5796
- DoS Slowhttptest      : 5499
- Heartbleed             : 11
- Name: count, dtype: int64

---
### Fisierele de mai jos sunt doar pentru analiza si logica:

analiza_dataset.py -> reprezinta fisierul de lucru unde am facut analiza pentru setul de date

main.py -> fisierul initial care prezinta logica

xlsx-raport.py -> fisierul ce combina rezultatele din fisierele xlsx intr-un singur xlsx