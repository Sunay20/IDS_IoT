import joblib
import pandas as pd

# Load the lightweight model, translator, and exact feature list
model = joblib.load('iot_detector_light.pkl')
label_encoder = joblib.load('label_encoder.pkl')
selected_features = joblib.load('selected_features.pkl')

print("Generating entirely NEW synthetic data (not from dataset)...")

# 1. Creating raw new data that mimics a DOS_SYN_Hping attack
new_data_1 = {
    'fwd_URG_flag_count': 0.0,
    'fwd_last_window_size': 64.0,
    'fwd_header_size_min': 20.0,
    'flow_iat.min': 2.5,  # Synthetically tweaked
    'fwd_PSH_flag_count': 0.0,
    'flow_FIN_flag_count': 0.0,
    'fwd_header_size_tot': 20.0,
    'flow_pkts_payload.max': 120.0,
    'fwd_pkts_payload.avg': 120.0,
    'service_mqtt': 0 # not mqtt
}

# 2. Creating raw new data that mimics an MQTT_Publish attack
new_data_2 = {
    'fwd_URG_flag_count': 0.0,
    'fwd_last_window_size': 500.0, # Synthetically tweaked
    'fwd_header_size_min': 32.0,
    'flow_iat.min': 450.0, # Synthetically tweaked
    'fwd_PSH_flag_count': 3.0,
    'flow_FIN_flag_count': 0.0,
    'fwd_header_size_tot': 340.0,
    'flow_pkts_payload.max': 35.0,
    'fwd_pkts_payload.avg': 8.0,
    'service_mqtt': 1 # is mqtt
}

# 3. Creating raw new data that mimics an ARP_poisioning attack
new_data_3 = {
    'fwd_URG_flag_count': 0.0,
    'fwd_last_window_size': 1300.0, # Synthetically tweaked
    'fwd_header_size_min': 13.0,
    'flow_iat.min': 24500.0, # Synthetically tweaked
    'fwd_PSH_flag_count': 2.0,
    'flow_FIN_flag_count': 0.0, # Synthetically tweaked
    'fwd_header_size_tot': 210.0,
    'flow_pkts_payload.max': 415.0, # Synthetically tweaked
    'fwd_pkts_payload.avg': 75.0,
    'service_mqtt': 0
}

# Put them into a DataFrame representing 3 distinct API requests
df_new = pd.DataFrame([new_data_1, new_data_2, new_data_3])

# Ensure columns perfectly match what the lightweight model expects
df_new = df_new.reindex(columns=selected_features, fill_value=0)

# Expected labels
expected_labels = ['DOS_SYN_Hping', 'MQTT_Publish', 'ARP_poisioning']

print("\n--- Running Predictions on SYNTHETIC New Data ---")
predictions = model.predict(df_new)
decoded_predictions = label_encoder.inverse_transform(predictions)

print("\n==================================================================================")
print(f"{'Synthetic Data Scenario':<30} | {'Expected Attack':<20} | {'Predicted Attack':<20}")
print("==================================================================================")

for i in range(len(df_new)):
    scenario = f"Mocked {expected_labels[i]} Data"
    expected = expected_labels[i]
    predicted = decoded_predictions[i]
    result = "[MATCH]" if expected == predicted else "[FAIL]"
    print(f"{scenario:<30} | {expected:<20} | {predicted:<20} | {result:<10}")

print("==================================================================================")
