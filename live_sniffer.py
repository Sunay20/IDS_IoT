import joblib
import pandas as pd
from nfstream import NFStreamer
from multiprocessing import freeze_support

def run_sniffer():
    # ==========================================
    # Phase 3: Real-Time Inference Loading
    # ==========================================
    print("Loading Lightweight IDS Model...")
    model = joblib.load('iot_detector_light.pkl')
    label_encoder = joblib.load('label_encoder.pkl')
    selected_features = joblib.load('selected_features.pkl')

    def map_nfstream_to_model(flow):
        is_mqtt = 1 if flow.application_name and 'mqtt' in str(flow.application_name).lower() else 0
        mapped_data = {
            'fwd_URG_flag_count': 0.0, 
            'fwd_PSH_flag_count': 0.0,
            'flow_FIN_flag_count': 0.0,
            
            # Using a safer default instead of total bytes, as TCP window size != payload size
            'fwd_last_window_size': 64.0, 
            'fwd_header_size_min': 20.0,
            'fwd_header_size_tot': float(flow.src2dst_packets * 20.0),
            
            'flow_iat.min': float(flow.bidirectional_min_piat_ms),
            'flow_pkts_payload.max': float(flow.bidirectional_max_ps),
            'fwd_pkts_payload.avg': float(flow.src2dst_mean_ps),
            'service_mqtt': is_mqtt
        }
        return mapped_data

    def mitigate_attack(attacker_ip, attack_type):
        print(f"    [DEFENSE] Initiating Automated Prevention Protocol...")
        # In a real deployment, this script would automatically execute a firewall command
        # like Windows 'netsh' or Linux 'iptables' to instantly drop the hacker's connection.
        firewall_cmd = f'netsh advfirewall firewall add rule name="Block_{attack_type}" dir=in action=block remoteip={attacker_ip}'
        print(f"    [FIREWALL] Executing: {firewall_cmd}")
        print(f"    [STATUS] Hacker IP ({attacker_ip}) is now QUARANTINED. Attack stopped.")

    def process_flow(flow):
        # FILTER NOISE: Ignore Windows background Multicast/Broadcast traffic
        if str(flow.dst_ip).startswith('224.') or str(flow.dst_ip).startswith('239.') or str(flow.dst_ip).startswith('ff02'):
            return
            
        features = map_nfstream_to_model(flow)
        df = pd.DataFrame([features]).reindex(columns=selected_features, fill_value=0)
        
        prediction = model.predict(df)[0]
        decoded_prediction = label_encoder.inverse_transform([prediction])[0]
        
        if decoded_prediction not in ['Thing_Speak', 'Normal']: 
            print(f"[ALERT] ATTACK DETECTED: {decoded_prediction}")
            print(f"    Target: {flow.dst_ip}:{flow.dst_port} | Source: {flow.src_ip}")
            mitigate_attack(flow.src_ip, decoded_prediction)
            print("-" * 50)

    print("=====================================================")
    print("Starting Real-Time IDS Sniffer...")
    print("Ensure you are running this terminal as Administrator!")
    print("=====================================================")

    try:
        streamer = NFStreamer(source=r"\Device\NPF_{64B07436-0D9E-446A-91A8-75E44CB1A0EA}", statistical_analysis=True, active_timeout=5)
        print("Listening for traffic flows... (Waiting for connections to finish or timeout)")
        for flow in streamer:
            process_flow(flow)
    except Exception as e:
        print(f"\n[ERROR] Failed to start sniffer: {e}")

if __name__ == '__main__':
    freeze_support()
    run_sniffer()
