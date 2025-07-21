import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import PowerTransformer, StandardScaler, MinMaxScaler, RobustScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_curve, auc
import matplotlib.pyplot as plt
from pyod.models.iforest import IForest
from pyod.models.ocsvm import OCSVM
from pyod.models.lof import LOF
from pyod.models.knn import KNN
from pyod.models.hbos import HBOS
from pyod.models.cblof import CBLOF

# =============================
# 1) Load Data and Clean
# =============================
def load_data(csv_path):
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    df['Label_str'] = df['Label'].astype(str)
    df['Label'] = df['Label'].astype(str).str.strip().str.upper().map(lambda x: 0 if x == 'BENIGN' else 1)
    df[['Flow Bytes/s', 'Flow Packets/s']] = df[['Flow Bytes/s', 'Flow Packets/s']].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=['Flow Bytes/s', 'Flow Packets/s'])
    return df


# =============================
# 2) Filtrare Date de Antrenare
# =============================
def filter_train_data(df, attacks_incl=None, keep_benign=True):
    if attacks_incl is None:
        attacks_incl = []

    df_filt = df.copy()
    labels_to_keep = []
    if keep_benign:
        labels_to_keep.append("BENIGN")
    labels_to_keep.extend(attacks_incl)

    if not labels_to_keep:
        print("[WARN] Nimic de păstrat => 0 rânduri.")
        return df_filt.iloc[0:0]

    mask = df_filt['Label_str'].isin(labels_to_keep)
    df_filt = df_filt[mask].copy()

    print(f"[INFO] Filtru => keep_benign={keep_benign}, attacks_incl={attacks_incl}")
    print("[INFO] Rezultatul are", df_filt.shape[0], "rânduri.")
    return df_filt


# =============================
# 3) Transformări (log / Yeo-Johnson)
# =============================
def apply_transformations_train(train_df, skew_threshold=1.0):
    train_trans = train_df.copy()
    transform_map = {}
    numeric_cols = train_trans.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        if col in ['Label']:
            continue
        skew_before = train_trans[col].skew()
        if abs(skew_before) > skew_threshold:
            if (train_trans[col] <= 0).any():
                print(f"[TRAIN] Col '{col}' skew={skew_before:.2f} => Yeo-Johnson.")
                pt = PowerTransformer(method='yeo-johnson')
                arr = train_trans[[col]]
                train_trans[col] = pt.fit_transform(arr)
                transform_map[col] = ('yj', pt)
                skew_after = train_trans[col].skew()
                print(f"   -> Noul skew={skew_after:.2f} (YJ).")
            else:
                print(f"[TRAIN] Col '{col}' skew={skew_before:.2f} => log1p.")
                train_trans[col] = np.log1p(train_trans[col])
                transform_map[col] = ('log', None)
                skew_after = train_trans[col].skew()
                print(f"   -> Noul skew={skew_after:.2f} (log).")
    return train_trans, transform_map


def apply_transformations_test(test_df, transform_map):
    test_trans = test_df.copy()
    for col, (method, transformer) in transform_map.items():
        if col not in test_trans.columns:
            continue
        if col == 'Label':
            continue
        if method == 'log':
            test_trans[col] = np.log1p(test_trans[col])
        elif method == 'yj':
            arr = test_trans[[col]]
            test_trans[col] = transformer.transform(arr)
    return test_trans


# =============================
# 4) Scalare
# =============================
def scale_train_standard(train_df):
    from sklearn.preprocessing import StandardScaler
    train_s = train_df.copy()
    numeric_cols = train_s.select_dtypes(include=[np.number]).columns.difference(['Label'])
    scaler = StandardScaler()
    scaler.fit(train_s[numeric_cols])
    train_s[numeric_cols] = scaler.transform(train_s[numeric_cols])
    return train_s, scaler


def scale_test_standard(test_df, scaler):
    test_s = test_df.copy()
    numeric_cols = test_s.select_dtypes(include=[np.number]).columns.difference(['Label'])
    test_s[numeric_cols] = scaler.transform(test_s[numeric_cols])
    return test_s


def scale_train_minmax(train_df):
    from sklearn.preprocessing import MinMaxScaler
    train_s = train_df.copy()
    numeric_cols = train_s.select_dtypes(include=[np.number]).columns.difference(['Label'])
    scaler = MinMaxScaler()
    scaler.fit(train_s[numeric_cols])
    train_s[numeric_cols] = scaler.transform(train_s[numeric_cols])
    return train_s, scaler


def scale_test_minmax(test_df, scaler):
    test_s = test_df.copy()
    numeric_cols = test_s.select_dtypes(include=[np.number]).columns.difference(['Label'])
    test_s[numeric_cols] = scaler.transform(test_s[numeric_cols])
    return test_s


def scale_train_robust(train_df):
    from sklearn.preprocessing import RobustScaler
    train_s = train_df.copy()
    numeric_cols = train_s.select_dtypes(include=[np.number]).columns.difference(['Label'])
    scaler = RobustScaler()
    scaler.fit(train_s[numeric_cols])
    train_s[numeric_cols] = scaler.transform(train_s[numeric_cols])
    return train_s, scaler


def scale_test_robust(test_df, scaler):
    test_s = test_df.copy()
    numeric_cols = test_s.select_dtypes(include=[np.number]).columns.difference(['Label'])
    test_s[numeric_cols] = scaler.transform(test_s[numeric_cols])
    return test_s


# =============================
# 5) Feature Engineering Functions
# =============================

#înlocuiește setul preprocesat cu noile caracteristici
def feature_engineering_only(df):
    df_fe = df.copy()
    df_fe['SynRate'] = df_fe['SYN Flag Count'] / (df_fe['Flow Duration'] + 1e-6)
    df_fe['PshRate'] = df_fe['PSH Flag Count'] / (df_fe['Flow Duration'] + 1e-6)
    df_fe['HeaderToPayloadRatio'] = (df_fe['Fwd Header Length'] + df_fe['Bwd Header Length']) / (df_fe['Flow Bytes/s'] + 1e-6)
    df_fe['SubflowBytesRatio'] = df_fe['Subflow Fwd Bytes'] / (df_fe['Subflow Bwd Bytes'] + 1e-6)
    df_fe['SynBurstScore'] = df_fe['SynRate'] * df_fe['Flow Packets/s']
    df_fe['IdleActiveImbalance'] = df_fe['Idle Mean'] / (df_fe['Active Mean'] + 1e-6)
    df_fe['BulkRateDiff'] = abs(df_fe['Fwd Avg Bulk Rate'] - df_fe['Bwd Avg Bulk Rate'])
    df_fe['BulkToPacketRate'] = df_fe['Fwd Avg Bulk Rate'] / (df_fe['Flow Packets/s'] + 1e-6)
    df_fe['FwdBwdPacketRatio'] = df_fe['Total Fwd Packets'] / (df_fe['Total Backward Packets'] + 1e-6)
    df_fe['PacketLengthRange'] = df_fe['Max Packet Length'] - df_fe['Min Packet Length']
    df_fe['FwdPacketAggression'] = df_fe['Fwd Packet Length Std'] / (df_fe['Fwd Packet Length Mean'] + 1e-6)

    engineered_cols = [
        'SynRate', 'PshRate', 'HeaderToPayloadRatio', 'SubflowBytesRatio', 'SynBurstScore',
        'IdleActiveImbalance', 'BulkRateDiff', 'BulkToPacketRate',
        'FwdBwdPacketRatio', 'PacketLengthRange', 'FwdPacketAggression'
    ]

    engineered_df = df_fe[engineered_cols].copy()
    engineered_df['Label'] = df['Label'].values
    engineered_df['Label_str'] = df['Label_str'].values
    return engineered_df

# adaugă caracteristici derivate la setul preprocesat
def feature_engineering_augmented(df):
    df_fe = df.copy()
    df_eng = feature_engineering_only(df)
    engineered_cols = df_eng.columns.difference(['Label', 'Label_str'])

    for col in engineered_cols:
        df_fe[col] = df_eng[col]

    df_fe['Label'] = df['Label']
    df_fe['Label_str'] = df['Label_str']
    return df_fe


def feature_engineering_app_specific(df):
    app_cols = [
        'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s',
        'SYN Flag Count', 'PSH Flag Count',
        'Fwd Header Length', 'Bwd Header Length',
        'Subflow Fwd Bytes', 'Subflow Bwd Bytes'
    ]
    df_out = df[app_cols].copy()
    df_out['Label'] = df['Label']
    df_out['Label_str'] = df['Label_str']
    return df_out



def feature_engineering_app_specific_plus_combined(df):
    df_app = feature_engineering_app_specific(df)
    df_eng = feature_engineering_only(df)
    engineered_cols = df_eng.columns.difference(['Label', 'Label_str'])

    df_combined = df_app.copy()
    for col in engineered_cols:
        df_combined[col] = df_eng[col]

    df_combined['Label'] = df['Label']
    df_combined['Label_str'] = df['Label_str']
    return df_combined


def fe_http_flood(df):
    eng = feature_engineering_only(df)
    df_out = pd.concat([
        df[['Flow Packets/s', 'Flow Bytes/s']],
        eng[['FwdBwdPacketRatio', 'PacketLengthRange']],
    ], axis=1)
    df_out['Label'] = df['Label']
    df_out['Label_str'] = df['Label_str']
    return df_out


def fe_slow_http(df):
    eng = feature_engineering_only(df)
    df_out = pd.concat([
        df[['Flow Duration', 'Idle Mean']],
        eng[['IdleActiveImbalance', 'PacketLengthRange']],
    ], axis=1)
    df_out['Label'] = df['Label']
    df_out['Label_str'] = df['Label_str']
    return df_out

def fe_syn_http_hybrid(df):
    eng = feature_engineering_only(df)
    df_out = pd.concat([
        df[['SYN Flag Count', 'Flow Packets/s']],
        eng[['SynRate', 'SynBurstScore']],
    ], axis=1)
    df_out['Label'] = df['Label']
    df_out['Label_str'] = df['Label_str']
    return df_out


# =============================
# 6) Antrenarea Modelului (pyod)
# =============================
def train_pyod_model(model_name, X_train, X_test, y_train=None, y_test=None):
    model = None
    if model_name == 'iforest':
        model = IForest()
    elif model_name == 'ocsvm':
        model = OCSVM()
    elif model_name == 'lof':
        model = LOF()
    elif model_name == 'knn':
        model = KNN()
    elif model_name == 'hbos':
        model = HBOS()
    elif model_name == 'cblof':
        model = CBLOF()
    else:
        print("[WARN] Model necunoscut => iforest default.")
        model = IForest()
    print(f"[INFO] Antrenam {model_name} pe {X_train.shape[0]} rânduri, {X_train.shape[1]} features.")
    model.fit(X_train)
    y_pred = model.predict(X_test)  # 0 = inlier, 1 = outlier
    if y_test is not None:
        print("[INFO] Classification Report:")
        print(classification_report(y_test, y_pred, digits=4))
    else:
        print("[INFO] Fără y_test => nu se poate evalua clasic.")
    return model, y_pred


# =============================
# 7) Meniuri Intermediare
# =============================
def meniu_filtrare():
    print("\n=== Meniu Filtrare Train ===")
    print("  1) Doar benign (Label_str='BENIGN')")
    print("  2) Benign + user typed attacks (ex: 'DoS Hulk,DDoS')")
    print("  3) Nicio filtrare (iau train tot)")
    print("  0) Iesire totala")


def meniu_preprocesare():
    print("\n=== Meniu Preprocesare ===")
    print("  1) Fără transform, fără scalare")
    print("  2) Transform, fără scalare")
    print("  3) Transform + StandardScaler")
    print("  4) Transform + MinMaxScaler")
    print("  5) Transform + RobustScaler")
    print("  0) Inapoi meniu filtrare")


def meniu_model():
    print("\n=== Meniu Model (pyod) ===")
    print("  1) IForest")
    print("  2) OCSVM")
    print("  3) LOF")
    print("  4) KNN")
    print("  5) HBOS")
    print("  6) CBLOF")
    print("  0) Inapoi meniu preprocesare")


def meniu_feature_eng():
    print("\n=== Meniu Feature Engineering ===")
    print("  1) NoFE  – Fără Results - feature engineering (set preprocesat)")
    print("  2) EngOnly  – Doar metrici derivate")
    print("  3) Aug  – Set original + metrici derivate")
    print("  4) AppSpec  – Doar caracteristici specifice aplicației")
    print("  5) AppSpec+Comb  – Specifice + derivate")
    print("  6) HTTPFlood  – Flow Packets/s, Flow Bytes/s, FwdBwdPacketRatio, PacketLengthRange")
    print("  7) SlowHTTP  – Flow Duration, Idle Mean, IdleActiveImbalance, PacketLengthRange")
    print("  8) SYNHTTPHybrid  – SYN Count, Flow Packets/s, SynRate, SynBurstScore")
    print("  0) NoMod  – (fallback fără modificări)")



# =============================
# 8) Fluxul Principal
# =============================
if __name__ == "__main__":
    csv_path = '/Wednesday-workingHours.pcap_ISCX.csv'
    df = load_data(csv_path)

    meniu_filtrare()
    f_choice = input("Alegere filtrare: ").strip()
    if f_choice == "0":
        print("Iesire TOTALA.")
        exit()
    if f_choice == "1":
        filter_option = 1
        attacks_incl = []
        keep_benign = True
    elif f_choice == "2":
        filter_option = 2
        user_atk = input("\nIntrodu tipuri de atac separate prin virgula: ").strip()
        if user_atk == "":
            attacks_incl = []
        else:
            attacks_incl = [x.strip() for x in user_atk.split(',')]
        keep_benign = True
    elif f_choice == "3":
        filter_option = 3
    else:
        print("Optiune invalida, iesire.")
        exit()

    meniu_preprocesare()
    p_choice = input("Alegere preproc: ").strip()
    if p_choice == "0":
        print("Revenire la filtrare, iesire.")
        exit()

    meniu_model()
    m_choice = input("Alegere model: ").strip()
    if m_choice == "0":
        print("Revenire la preprocesare, iesire.")
        exit()

    # Mapează opțiunea de model
    if m_choice == "1":
        model_type = 'iforest'
    elif m_choice == "2":
        model_type = 'ocsvm'
    elif m_choice == "3":
        model_type = 'lof'
    elif m_choice == "4":
        model_type = 'knn'
    elif m_choice == "5":
        model_type = 'hbos'
    elif m_choice == "6":
        model_type = 'cblof'
    else:
        model_type = 'iforest'

    # Definirea numelui de scenariu:
    # se adauga o scurtă reprezentare pentru feature engineering
    fe_map = {
        "1": "NoFE",
        "2": "EngOnly",
        "3": "Aug",
        "4": "AppSpec",
        "5": "AppSpec+Comb",
        "6": "HTTPFlood",
        "7": "SlowHTTP",
        "8": "SYNHTTPHybrid",
        "0": "NoMod"
    }
    # Construim numele scenariului în funcție de opțiunea de filtrare și preprocesare
    if f_choice == "2":
        if len(attacks_incl) > 0:
            scenario_attacks = "-".join(a.replace(" ", "_") for a in attacks_incl)
        else:
            scenario_attacks = "NoAttackTyped"
        scenario_name = f"Filtrare{f_choice}_{scenario_attacks}_Preproc{p_choice}_Model{m_choice}_FE"
    else:
        scenario_name = f"Filtrare{f_choice}_Preproc{p_choice}_Model{m_choice}_FE"

    # Meniul de Feature Engineering se solicită o singură dată
    meniu_feature_eng()
    fe_choice = input("Alegere feature engineering: ").strip()
    fe_short = fe_map.get(fe_choice, "NoMod")
    scenario_name = f"{scenario_name}_{fe_short}"
    print(f"\n[INFO] Scenariul selectat => {scenario_name}")

    # Automatizarea testelor (10 rulari)
    num_tests = 10
    metrics_list = []
    roc_auc_list = []
    confusion_data = []  # Pentru matricea de confuzie
    roc_curves = []  # Pentru curbele ROC

    for i in range(num_tests):
        print(f"\n===== Test {i + 1} din {num_tests} =====")
        train_df, test_df = train_test_split(df, test_size=0.3, random_state=42 + i, shuffle=True)
        print(f"[INFO] train_df shape: {train_df.shape}, test_df shape: {test_df.shape}")

        # Filtrare
        if f_choice in ["1", "2"]:
            train_filtered = filter_train_data(train_df, attacks_incl=attacks_incl, keep_benign=keep_benign)
        elif f_choice == "3":
            train_filtered = train_df.copy()
            print("[INFO] Fără filtrare => tot train.")
        else:
            print("[WARN] Filtrare invalidă, iesire.")
            break

        # Preprocesare
        if p_choice == "1":
            print("[INFO] Fără transform, fără scalare.")
            train_final = train_filtered.copy()
            test_final = test_df.copy()
        elif p_choice == "2":
            print("[INFO] Transform (log/YJ), fără scalare.")
            train_final, tmap = apply_transformations_train(train_filtered.copy())
            test_final = apply_transformations_test(test_df.copy(), tmap)
        elif p_choice == "3":
            print("[INFO] Transform + StandardScaler.")
            train_t, map_t = apply_transformations_train(train_filtered.copy())
            test_t = apply_transformations_test(test_df.copy(), map_t)
            train_final, sc_std = scale_train_standard(train_t)
            test_final = scale_test_standard(test_t, sc_std)
        elif p_choice == "4":
            print("[INFO] Transform + MinMaxScaler.")
            train_t, map_t = apply_transformations_train(train_filtered.copy())
            test_t = apply_transformations_test(test_df.copy(), map_t)
            train_final, sc_mm = scale_train_minmax(train_t)
            test_final = scale_test_minmax(test_t, sc_mm)
        elif p_choice == "5":
            print("[INFO] Transform + RobustScaler.")
            train_t, map_t = apply_transformations_train(train_filtered.copy())
            test_t = apply_transformations_test(test_df.copy(), map_t)
            train_final, sc_rb = scale_train_robust(train_t)
            test_final = scale_test_robust(test_t, sc_rb)
        else:
            print("[WARN] Opțiune preproc invalidă, folosim seturile brute.")
            train_final = train_filtered.copy()
            test_final = test_df.copy()

        # Aplicare Feature Engineering
        if fe_choice == "1":
            print("[INFO] Nu se aplică feature engineering; se folosește setul preprocesat așa cum este.")
        elif fe_choice == "2":
            print("[INFO] se aplica feature engineering: Engineered features only.")
            train_final = feature_engineering_only(train_final)
            test_final = feature_engineering_only(test_final)
        elif fe_choice == "3":
            print("[INFO] se aplica feature engineering: Augmented data (original + derivate).")
            train_final = feature_engineering_augmented(train_final)
            test_final = feature_engineering_augmented(test_final)
        elif fe_choice == "4":
            print("[INFO] se aplica feature engineering: Application-specific features only.")
            train_final = feature_engineering_app_specific(train_final)
            test_final = feature_engineering_app_specific(test_final)
        elif fe_choice == "5":
            print("[INFO] se aplica feature engineering: Application-specific features + Combined engineered features.")
            train_final = feature_engineering_app_specific_plus_combined(train_final)
            test_final = feature_engineering_app_specific_plus_combined(test_final)
        elif fe_choice == "6":
            print("[INFO] se aplica feature engineering: HTTPFlood – subset HTTP flood")
            train_final = fe_http_flood(train_final)
            test_final = fe_http_flood(test_final)
        elif fe_choice == "7":
            print("[INFO] se aplica feature engineering: SlowHTTP – subset slowloris")
            train_final = fe_slow_http(train_final)
            test_final = fe_slow_http(test_final)
        elif fe_choice == "8":
            print("[INFO] se aplica feature engineering: SYNHTTPHybrid – subset SYN+HTTP hybrid")
            train_final = fe_syn_http_hybrid(train_final)
            test_final = fe_syn_http_hybrid(test_final)
        else:
            print("[WARN] Opțiune feature engineering invalidă, se folosește setul preprocesat.")

        # Pregătirea datelor pentru model
        X_train = train_final.drop(columns=['Label', 'Label_str'], errors='ignore')
        y_train = train_final['Label'].values if 'Label' in train_final.columns else None
        X_test = test_final.drop(columns=['Label', 'Label_str'], errors='ignore')
        y_test = test_final['Label'].values if 'Label' in test_final.columns else None

        # Antrenarea modelului
        model, y_pred = train_pyod_model(model_type, X_train, X_test, y_train, y_test)

        # Colectarea raportului de evaluare
        report = classification_report(y_test, y_pred, output_dict=True, digits=4)
        metrics_list.append(report)

        # Calcularea matricei de confuzie
        cm = confusion_matrix(y_test, y_pred)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
        else:
            tn = fp = fn = tp = None
        confusion_data.append((tn, fp, fn, tp))

        if None not in (tn, fp, fn, tp):
            print(f"[INFO] Confusion Matrix (Test {i + 1}): TP={tp}, TN={tn}, FP={fp}, FN={fn}")
        else:
            print(f"[WARN] Confusion Matrix invalidă (Test {i + 1}) – nu este binară.")

        # Calcularea curbei ROC și AUC (dacă modelul are decision_function)
        if hasattr(model, 'decision_function'):
            scores = model.decision_function(X_test)
            fpr, tpr, thresholds = roc_curve(y_test, scores)
            roc_auc = auc(fpr, tpr)
            roc_auc_list.append(roc_auc)
            roc_curves.append((fpr, tpr, roc_auc))
            print(f"[INFO] ROC AUC = {roc_auc:.4f}")
        else:
            roc_auc_list.append(None)
            roc_curves.append(None)
            print("[INFO] Modelul nu suportă decision_function pentru ROC curve.")

        print(f"[INFO] Rezultate Test {i + 1}:")
        print(report)

    # Calcularea mediilor metricilor
    accs = [rep["accuracy"] for rep in metrics_list]
    precision_class1 = [rep["1"]["precision"] for rep in metrics_list]
    recall_class1 = [rep["1"]["recall"] for rep in metrics_list]
    f1_class1 = [rep["1"]["f1-score"] for rep in metrics_list]

    avg_acc = np.mean(accs)
    avg_precision = np.mean(precision_class1)
    avg_recall = np.mean(recall_class1)
    avg_f1 = np.mean(f1_class1)
    valid_auc = [val for val in roc_auc_list if val is not None]
    avg_roc_auc = np.mean(valid_auc) if valid_auc else None

    print("\n===== Raport Final (Medii din {} teste) =====".format(num_tests))
    print("Average Accuracy: {:.4f}".format(avg_acc))
    print("Average Precision for class 1 (atac): {:.4f}".format(avg_precision))
    print("Average Recall for class 1 (atac): {:.4f}".format(avg_recall))
    print("Average F1-score for class 1 (atac): {:.4f}".format(avg_f1))
    if avg_roc_auc is not None:
        print("Average ROC AUC: {:.4f}".format(avg_roc_auc))

    # Construirea DataFrame-ului cu rezultatele testelor
    results_data = []
    for idx, rep in enumerate(metrics_list):
        row = {}
        row['Test'] = idx + 1
        row['Accuracy'] = rep["accuracy"]
        row['Precision_Atac'] = rep["1"]["precision"]
        row['Recall_Atac'] = rep["1"]["recall"]
        row['F1_Atac'] = rep["1"]["f1-score"]
        tn, fp, fn, tp = confusion_data[idx]
        row['TN'] = tn
        row['FP'] = fp
        row['FN'] = fn
        row['TP'] = tp
        row['ROC_AUC'] = roc_auc_list[idx]
        results_data.append(row)
    results_df = pd.DataFrame(results_data)

    # Adăugarea unei linii cu mediile calculate
    avg_row = {
        'Test': 'Average',
        'Accuracy': avg_acc,
        'Precision_Atac': avg_precision,
        'Recall_Atac': avg_recall,
        'F1_Atac': avg_f1,
        'TN': None,
        'FP': None,
        'FN': None,
        'TP': None,
        'ROC_AUC': avg_roc_auc
    }
    avg_row_df = pd.DataFrame([avg_row])
    results_df = pd.concat([results_df, avg_row_df], ignore_index=True)

    excel_name = f"raport_detectie_scenariu_{scenario_name}.xlsx"
    results_df.to_excel(excel_name, index=False)
    print(f"[INFO] Rezultatele au fost salvate în '{excel_name}'.")

    # Generarea unei singure diagrame care suprapune toate curbele ROC
    cmap = plt.get_cmap('rainbow')
    plt.figure(figsize=(8, 6))
    found_curve = False
    for idx, item in enumerate(roc_curves):
        if item is not None:
            fpr, tpr, auc_val = item
            plt.plot(fpr, tpr, color=cmap(idx / num_tests), alpha=0.8, label=f"Test {idx + 1} (AUC={auc_val:.4f})")
            found_curve = True
    if found_curve:
        plt.plot([0, 1], [0, 1], linestyle='--', color='gray')
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title(f"ROC Curves - {scenario_name} - {num_tests} tests")
        plt.legend(loc="lower right")
        roc_filename = f"roc_curves_{scenario_name}.png"
        plt.savefig(roc_filename, dpi=300)
        plt.show()
        print(f"[INFO] Diagrama ROC a fost salvată în '{roc_filename}'.")
    else:
        print("[INFO] Nicio curba ROC nu a fost generată, deoarece modelul nu suportă decision_function.")
