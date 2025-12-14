# --- 1. IMPORT LIBRARIES ---
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import joblib

# --- 2. LOAD DATASET ---
df = pd.read_csv("ai.csv")
print("Dataset loaded:", df.shape)
# --- 3. REMOVE DUPLICATES ---
df.drop_duplicates(inplace=True)
print("After dropping duplicates:", df.shape)

# --- 4. DROP CONSTANT COLUMNS (BEFORE FEATURE ENGINEERING) ---
constant_cols = [c for c in df.columns if df[c].nunique() == 1]
df.drop(columns=constant_cols, inplace=True)
print("Dropped constant columns:", constant_cols)

# --- 5. HANDLE MISSING VALUES (Fill with median) ---
df.fillna(df.median(numeric_only=True), inplace=True)

# --- 6. CAP OUTLIERS ---
cap_cols = [
    'domain_spf', 'time_domain_expiration', 'time_response',
    'qty_ip_resolved', 'qty_mx_servers',
    'length_url', 'qty_hyphen_domain', 'file_length'
]
for col in cap_cols:
    if col in df.columns:
        Q1 = df[col].quantile(0.25)
        Q3 = df[col].quantile(0.75)
        IQR = Q3 - Q1
        lower = Q1 - 1.5 * IQR
        upper = Q3 + 1.5 * IQR
        df[col] = np.where(df[col] < lower, lower,
                           np.where(df[col] > upper, upper, df[col]))

print("Outliers capped.")

# --- 7. FEATURE ENGINEERING ---
if {'time_domain_expiration', 'time_domain_activation'}.issubset(df.columns):
    df['domain_age_days'] = df['time_domain_expiration'] - df['time_domain_activation']

if {'qty_dot_domain', 'domain_length'}.issubset(df.columns):
    df['dots_per_domain'] = df['qty_dot_domain'] / df['domain_length'].replace(0, 1)

if {'qty_vowels_domain', 'domain_length'}.issubset(df.columns):
    df['vowels_ratio_domain'] = df['qty_vowels_domain'] / df['domain_length'].replace(0, 1)

if {'qty_dot_url', 'length_url'}.issubset(df.columns):
    df['qty_dot_url_ratio'] = df['qty_dot_url'] / df['length_url'].replace(0, 1)

print("Feature engineering applied.")

# --- 8. DROP CONSTANT COLUMNS AFTER FEATURE ENGINEERING ---
constant_cols_after = [c for c in df.columns if df[c].nunique() == 1]
df.drop(columns=constant_cols_after, inplace=True)
print("Post-engineering constant columns dropped:", constant_cols_after)

print("Shape before scaling:", df.shape)

# --- 9. SCALING ---
numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
numeric_cols.remove('phishing')

scaler = StandardScaler()
df[numeric_cols] = scaler.fit_transform(df[numeric_cols])

print("Scaling complete.")
# --- 10. FINAL DATA PREP ---
X = df.drop(columns=['phishing'])
y = df['phishing'].astype(int)

# Save final dataset
df.to_csv("final_dataset.csv", index=False)
print("Saved final_dataset.csv")

# Save scaler
joblib.dump(scaler, "scaler.pkl")
print("Saved scaler.pkl")

# --- 11. TRAIN-TEST SPLIT ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Training features count:", X_train.shape[1])

# --- 12. MODELS ---
models = {
    "RandomForest": RandomForestClassifier(n_estimators=200, random_state=42),
    "XGBoost": XGBClassifier(eval_metric='logloss', random_state=42),
    "LightGBM": LGBMClassifier(random_state=42),
    "LogisticRegression": LogisticRegression(max_iter=2000, random_state=42)
}

results = []
best_model_name = None
best_model_score = -1
best_model_obj = None

# --- 13. TRAIN & EVALUATE ---
for name, model in models.items():
    print(f"\n{'='*12} {name} {'='*12}")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:,1] if hasattr(model, "predict_proba") else None

    acc = accuracy_score(y_test, y_pred)

    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc = roc_auc_score(y_test, y_prob) if y_prob is not None else 0

    results.append([name, acc, prec, rec, f1, roc])

    if acc > best_model_score:
        best_model_score = acc
        best_model_name = name
        best_model_obj = model

# --- 14. SAVE BEST MODEL ---
joblib.dump(best_model_obj, "best_model.pkl")
print(f"\nBest Model Saved: {best_model_name} → best_model.pkl")

# --- 15. SHOW RESULTS ---
results_df = pd.DataFrame(results, columns=["Model", "Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"])
print("\n========== FINAL RESULTS ==========")
print(results_df)




