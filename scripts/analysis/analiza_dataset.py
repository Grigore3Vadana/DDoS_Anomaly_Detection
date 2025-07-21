# libraries
import os
import pandas as pd
import numpy as np
from openpyxl.drawing.image import Image
from openpyxl.workbook import Workbook
import matplotlib.pyplot as plt
import re

# dataframe
dataframe = pd.read_csv('/Wednesday-workingHours.pcap_ISCX.csv')
dataframe.columns = dataframe.columns.str.strip()

# ====================================
# ---- Informatii despre dataset ----
# ====================================

#print(dataframe.head())
#print(dataframe.shape)
#print(dataframe.isnull())
#print(dataframe.describe())
"""
# ====================================
# ---- descrierea caracteristicilor folosite in Results - feature engineering ----
# ====================================

epsilon = 1e-9
dataframe['PacketLengthRange'] = (dataframe['Max Packet Length'] - dataframe['Min Packet Length'])
dataframe['FwdPacketAggression'] = (dataframe['Fwd Packet Length Std'] / (dataframe['Fwd Packet Length Mean'] + epsilon))
dataframe['IdleActiveImbalance'] = (dataframe['Idle Mean'] / (dataframe['Active Mean'] + epsilon))
dataframe['SynRate'] = (dataframe['SYN Flag Count'] / (dataframe['Flow Duration'] + epsilon))
dataframe['SynBurstScore'] = (dataframe['SynRate'] * dataframe['Flow Packets/s'])

columns_to_describe = [
    'Flow Packets/s',
    'Flow Bytes/s',
    'SynRate',
    'SynBurstScore',
]

existing_cols=[col for col in columns_to_describe if col in dataframe.columns]
summary=dataframe[existing_cols].describe()
summary.to_csv('statistici_caracteristici_dos.csv')"""

# ====================================
# ---- Verificare coloanelor NaN ----
# ====================================
"""
exista_NaN = dataframe.isnull().values.any()
print("Exista NaN?", exista_NaN)

NaN_pe_coloana = dataframe.isnull().sum()
coloane_cu_NaN = NaN_pe_coloana[NaN_pe_coloana > 0]
print("Coloane cu valori NaN:")
print(coloane_cu_NaN)


# ========================
# -- Coloanele numerice --
# ========================

print("toate coloanele numerice")
numerical_columns = dataframe.select_dtypes(include=['int64', 'float64']).columns
print(numerical_columns)

# =========================
# -- Distributia Datelor --
# =========================


print("distributia datelor")
distribution = dataframe["Label"].value_counts()
print(distribution)
plt.figure(figsize=(10, 6))
distribution.plot(kind="bar", color=["skyblue", "salmon", "lightgreen"])
plt.title("Distributia etichetelor 'LABEL'")
plt.xlabel("Etichete")
plt.ylabel("Numar de aparitii")
plt.xticks(rotation=45)
plt.grid(axis="y", linestyle="--", alpha=0.7)
for i, count in enumerate(distribution):
    plt.text(i, count + 0.1, str(count), ha="center", va="bottom")
plt.show()


# =========================
# Verificarea valorilor infinit
# =========================


inf_pe_coloana = dataframe.isin([np.inf, -np.inf]).sum()
# se păstrează doar coloanele care au cel puțin o valoare infinită
coloane_cu_inf = inf_pe_coloana[inf_pe_coloana > 0]
print("Coloane cu valori infinite:")
print(coloane_cu_inf)

# Pentru 'Flow Bytes/s'
rows_flow_bytes = dataframe[dataframe['Flow Bytes/s'].isin([np.inf, -np.inf])]
print("Rânduri cu valori infinite în 'Flow Bytes/s':")
print(rows_flow_bytes[['Flow Bytes/s']])

# Pentru 'Flow Packets/s'
rows_flow_packets = dataframe[dataframe['Flow Packets/s'].isin([np.inf, -np.inf])]
print("Rânduri cu valori infinite în 'Flow Packets/s':")
print(rows_flow_packets[['Flow Packets/s']])

print("Flow Bytes/s:", repr(dataframe.loc[1392, 'Flow Bytes/s']))
print("Flow Packets/s:", repr(dataframe.loc[1392, 'Flow Packets/s']))


# ===========================
# Verificarea RANDURILOR ce contin valorile NaN
#===========================

rows_with_nan = dataframe[dataframe.isna().any(axis=1)]
# Iterăm peste rândurile care au NaN și afișăm coloanele afectate pentru fiecare
for index, row in rows_with_nan.iterrows():
    # Găsim coloanele unde valoarea este NaN
    columns_with_nan = row[row.isna()].index.tolist()
    print(f"Rândul {index} are valori NaN în coloanele: {columns_with_nan}")

# ==============================================================================
# Eliminarea valorilor NaN si Infinit din coloanele Flow bytes/s si Flow packets, adica a randurilor ce contin, nu si coloanele
# Folosirea unui nou dataframe, numit new_df
# Noul dataframe este curatat, nu mai contine valori NaN sau Infinit
# =============================================================================
"""
df_copy = dataframe.copy()
df_copy[['Flow Bytes/s', 'Flow Packets/s']] = df_copy[['Flow Bytes/s', 'Flow Packets/s']].replace([np.inf, -np.inf], np.nan)
new_df = df_copy.dropna(subset=['Flow Bytes/s', 'Flow Packets/s'])
"""
#print(dataframe.describe())

# ================================
# Reverificare pentru a vedea daca mai exista valori NaN sau infinit
# ================================

#print("Număr total NaN:", new_df.isna().sum().sum())
#print("Număr total Infinity:", new_df.isin([np.inf, -np.inf]).sum().sum())

# ================================
# analiza - Histograme
# ================================


image_dir = "histograms"
os.makedirs(image_dir, exist_ok=True)

# Creează un fișier Excel
wb = Workbook()
ws = wb.active
ws.title = "Histograme"

# Setări pentru plasarea imaginilor în coloane și rânduri
cols_per_row = 5  # Câte coloane pe rând
cell_width = 50  # Lățimea coloanelor
cell_height = 95  # Înălțimea rândurilor

# Redimensionează coloanele și rândurile pentru imagini
for col in range(cols_per_row):
    ws.column_dimensions[chr(65 + col)].width = cell_width  # A, B, C, ...


# Funcție pentru a curăța numele fișierelor
def clean_filename(name):
    return re.sub(r'[^\w\-_\. ]', '_', name)  # Înlocuiește caracterele speciale cu '_'


# Generează histograme și le salvează ca imagini
for i, column in enumerate(new_df.columns):
    if new_df[column].dtype in ['int64', 'float64']:  # Ignoră coloanele non-numerice
        plt.figure(figsize=(4, 3))
        new_df[column].hist(bins=20)
        plt.title(column)
        plt.tight_layout()

        # Curăță numele fișierului
        safe_column_name = clean_filename(column)
        image_path = os.path.join(image_dir, f"{safe_column_name}.png")

        # Salvează imaginea
        plt.savefig(image_path, dpi=100)
        plt.close()

        # Calculează poziția imaginii în grilă (6 coloane pe rând)
        row = (i // cols_per_row) * 20 + 1  # Ocupă câte 20 de rânduri per rând de imagini
        col = i % cols_per_row  # Coloana în Excel (A, B, C, D, etc.)
        cell = f"{chr(65 + col)}{row}"  # Ex: A1, B1, ..., F1, apoi A21, B21, ...

        # Inserează imaginea
        img = Image(image_path)
        ws.add_image(img, cell)

# Salvează fișierul Excel
wb.save("histograms.xlsx")
print("Fișierul Excel cu histograme ordonate pe coloane a fost creat!")

# ====================
# analiza - Box-plot
# =====================


def save_boxplots_to_excel(df, output_file):
    wb = Workbook()
    ws = wb.active
    ws.title = "Boxplots"

    temp_dir = "boxplots"
    os.makedirs(temp_dir, exist_ok=True)

    cols_per_row = 5  # Câte coloane pe rând
    cell_width = 50  # Lățimea coloanelor
    cell_height = 95  # Înălțimea rândurilor

    # Redimensionează coloanele și rândurile pentru imagini
    for col in range(cols_per_row):
        ws.column_dimensions[chr(65 + col)].width = cell_width  # A, B, C, ...

    # Funcție pentru a curăța numele fișierelor
    def clean_filename(name):
        return re.sub(r'[^\w\-_\. ]', '_', name)  # Înlocuiește caracterele speciale cu '_'

    # Selectează doar coloanele numerice
    numeric_columns = df.select_dtypes(include=["number"]).columns

    for i, column in enumerate(numeric_columns):
        fig, ax = plt.subplots(figsize=(4, 3))
        df.boxplot(column=column, ax=ax)

        # Curăță numele fișierului
        safe_column_name = clean_filename(column)
        img_path = os.path.join(temp_dir, f"{safe_column_name}.png")

        plt.savefig(img_path, dpi=100)
        plt.close(fig)

        # Calculează poziția imaginii în grilă
        row = (i // cols_per_row) * 20 + 1  # Ocupă câte 20 de rânduri per rând de imagini
        col = i % cols_per_row  # Coloana în Excel (A, B, C, D, etc.)
        cell = f"{chr(65 + col)}{row}"  # Ex: A1, B1, ..., F1, apoi A21, B21, ...

        img = Image(img_path)
        ws.add_image(img, cell)

    wb.save(output_file)
    print("Fișierul Excel cu boxplot-uri ordonate pe coloane a fost creat!")

    # Șterge imaginile temporare
    for file in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, file))
    os.rmdir(temp_dir)

# Exemplu de utilizare:
save_boxplots_to_excel(new_df, "boxplots.xlsx")

# =============================================
# coloane categorice (e.g. flow bytes/s) numarul valori in functie de numarul portului
# =============================================
#print(new_df['Flow Bytes/s'].value_counts())

"""
# ===================================
# skewness
# Asimetria măsoară deviația distribuției față de simetrie
# ====================================
# am copiat linia de la coloane numerice de mai sus si # pe cea initiala

numerical_columns_new_df = new_df.select_dtypes(include=['int64', 'float64']).columns
skew_values = new_df[numerical_columns_new_df].skew()
print("Skewness pentru fiecare coloană:")
print(skew_values)

# ===============================
# varianta pentru fiecare coloana
# Varianta reprezinta cât de dispersate sunt valorile față de medie
# ===============================

variance_values = new_df[numerical_columns_new_df].var()
print("Varianta pentru fiecare coloană:")
print(variance_values)


