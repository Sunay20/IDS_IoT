import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder

# ==========================================
# 1. DATA LOADING & ROBUST CLEANING
# ==========================================
print("Loading dataset...")
df = pd.read_csv('RT_IOT2022')

if 'Unnamed: 0' in df.columns:
    df = df.drop(columns=['Unnamed: 0'])

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# ==========================================
# 2. FEATURE ENGINEERING
# ==========================================
X = df.drop(columns=['Attack_type', 'id.orig_p', 'id.resp_p'])
y = df['Attack_type']

X = pd.get_dummies(X, columns=['proto', 'service'], drop_first=True)

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# ==========================================
# 3. STRATIFIED DATA SPLITTING
# ==========================================
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

# ==========================================
# 4. HYPERPARAMETER TUNING & TRAINING (Full Model)
# ==========================================
param_dist = {
    'n_estimators': [100, 200, 300],
    'max_depth': [10, 20, None],
    'min_samples_split': [2, 5, 10],
    'max_features': ['sqrt', 'log2']
}

rf_base = RandomForestClassifier(class_weight='balanced', random_state=42)

print("Starting Randomized Search for optimal hyperparameters...")
rf_search = RandomizedSearchCV(
    estimator=rf_base, 
    param_distributions=param_dist, 
    n_iter=5, 
    cv=3, 
    n_jobs=-1, 
    random_state=42, 
    verbose=1
)

rf_search.fit(X_train, y_train)
best_rf = rf_search.best_estimator_

# ==========================================
# 5. NEW: MODEL PRUNING (Selecting Top 10 Features)
# ==========================================
print("\n--- Starting Model Pruning ---")
importances = best_rf.feature_importances_
feat_importances = pd.Series(importances, index=X.columns)

# Select the Top 10 Features
top_10_features = feat_importances.nlargest(10).index.tolist()
print(f"Top 10 Features Selected for Pruning: {top_10_features}")

# Filter the data to only include these 10 features
X_train_pruned = X_train[top_10_features]
X_test_pruned = X_test[top_10_features]

# Train the "Light" version using the best parameters from our search
pruned_rf = RandomForestClassifier(
    **rf_search.best_params_, 
    class_weight='balanced', 
    random_state=42, 
    n_jobs=-1
)
pruned_rf.fit(X_train_pruned, y_train)

# ==========================================
# 6. EVALUATION
# ==========================================
# Evaluate Full Model
y_pred_full = best_rf.predict(X_test)
full_acc = accuracy_score(y_test, y_pred_full)

# Evaluate Pruned Model
y_pred_pruned = pruned_rf.predict(X_test_pruned)
pruned_acc = accuracy_score(y_test, y_pred_pruned)

print("\n--- ACCURACY COMPARISON ---")
print(f"Full Model (80+ features): {full_acc:.4f}")
print(f"Pruned Model (10 features): {pruned_acc:.4f}")

# ==========================================
# 7. SAVE BOTH MODELS
# ==========================================
# Save the Full Model
joblib.dump(best_rf, 'iot_intrusion_detector.pkl')

# Save the Pruned Model and its specific Feature List
joblib.dump(pruned_rf, 'iot_detector_light.pkl')
joblib.dump(top_10_features, 'selected_features.pkl')

# Save the Translator
joblib.dump(label_encoder, 'label_encoder.pkl')

# Save Test Data for Audit (Prevents Data Leakage)
joblib.dump(X_test_pruned, 'X_test_pruned.pkl')
joblib.dump(y_test, 'y_test.pkl')

print("\nAll models, metadata, and test datasets saved successfully.")