import joblib
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

# 1. Load the Light Brain, Translator, and Test Data
print("Loading model and unseen test data...")
model = joblib.load('iot_detector_light.pkl')
label_encoder = joblib.load('label_encoder.pkl')
selected_features = joblib.load('selected_features.pkl')

# Load the exact test set split from the training pipeline to prevent data leakage
try:
    X_test_pruned = joblib.load('X_test_pruned.pkl')
    y_test = joblib.load('y_test.pkl')
except FileNotFoundError:
    print("Error: Test data not found. Please re-run iot.py first to generate the test datasets.")
    exit(1)

# 2. Run the Audit
print("🚀 Running full audit on the Lightweight Model (Unseen Data)...")
y_pred = model.predict(X_test_pruned)

# 3. Show the Performance Report
print("\n--- LIGHT MODEL PERFORMANCE BY CATEGORY ---")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

# 4. Optional: Save the Final Audit Matrix
plt.figure(figsize=(12, 10))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
plt.title('Lightweight Model: Final Detection Matrix (Unseen Data)')
plt.ylabel('Actual Attack')
plt.xlabel('Predicted Attack')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()