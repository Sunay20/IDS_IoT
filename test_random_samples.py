import joblib
import pandas as pd
import numpy as np

# Load everything
model = joblib.load('iot_detector_light.pkl')
label_encoder = joblib.load('label_encoder.pkl')
selected_features = joblib.load('selected_features.pkl')

print("Loading original dataset to pick random samples...")
df = pd.read_csv('RT_IOT2022')
if 'Unnamed: 0' in df.columns:
    df = df.drop(columns=['Unnamed: 0'])

# Clean as per original script
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Pick 15 random rows with a random seed so it changes every run
random_samples = df.sample(n=15, random_state=np.random.randint(0, 10000))

# Save the true labels for comparison
true_labels = random_samples['Attack_type'].values

# Drop the columns we don't need for features
X_random = random_samples.drop(columns=['Attack_type', 'id.orig_p', 'id.resp_p'])

# One-hot encode what's available
X_random_encoded = pd.get_dummies(X_random)

# Reindex to match EXACTLY the 10 features the lightweight model expects
X_random_final = X_random_encoded.reindex(columns=selected_features, fill_value=0)

# Predict
print("\n--- Running predictions on 15 completely random network traffic samples ---")
predictions = model.predict(X_random_final)

# Decode predictions back to string labels
decoded_predictions = label_encoder.inverse_transform(predictions)

# Display results
print("\n=======================================================================")
print(f"{'Sample #':<10} | {'Actual Type':<25} | {'Predicted Type':<25} | {'Result':<10}")
print("=======================================================================")

correct_count = 0
for i in range(15):
    actual = true_labels[i]
    predicted = decoded_predictions[i]
    result = "[PASS]" if actual == predicted else "[FAIL]"
    if actual == predicted:
        correct_count += 1
    
    print(f"{i+1:<10} | {actual:<25} | {predicted:<25} | {result:<10}")

print("=======================================================================")
print(f"Accuracy on this random batch: {correct_count}/15 ({(correct_count/15)*100:.2f}%)")
print("\nTip: Run this script again to grab a completely different set of 15 random rows!")
