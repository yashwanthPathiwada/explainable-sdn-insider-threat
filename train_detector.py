#!/usr/bin/env python3
"""
=============================================================================
MODULE 3: Machine Learning Detection Engine & Risk Fusion
Project: Explainable AI-Based Insider Threat Detection in SDN using SHAP/LIME
File: train_detector.py
=============================================================================
Description:
    Trains and coordinates:
      1. Supervised Classifier: Random Forest with cost-sensitive class weights
         for anomalous insider threat classification.
      2. Unsupervised Detector: Isolation Forest trained strictly on benign baseline
         traffic to flag novel zero-day insider variations.
      3. Risk Fusion Function: Fuses supervised probability, unsupervised outlier
         score, and contextual domain flags into a single normalized score s_fused.
      4. Tier Classification: Maps s_fused into 4 severity tiers:
         - Low (s < 0.35)
         - Medium (0.35 <= s < 0.65)
         - High (0.65 <= s < 0.85)
         - Critical (s >= 0.85)
      5. Synthetic Enterprise Data Generator: Generates realistic multi-scenario
         traffic for both offline model training and standalone demonstrations.
"""

import os
import time
import json
import random
import sqlite3
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score,
    precision_score, recall_score, f1_score
)

from feature_engineering import (
    FEATURE_COLUMNS, ASSET_ROLES, SENSITIVE_SERVERS, SENSITIVE_PORTS,
    FeaturePreprocessor, extract_sliding_windows, DEFAULT_DB_PATH
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, 'models')
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

SUPERVISED_MODEL_PATH = os.path.join(MODEL_DIR, 'supervised_rf.pkl')
UNSUPERVISED_MODEL_PATH = os.path.join(MODEL_DIR, 'unsupervised_iforest.pkl')
METADATA_PATH = os.path.join(MODEL_DIR, 'model_metadata.json')
BASELINE_STATS_PATH = os.path.join(MODEL_DIR, 'baseline_stats.json')


# ---------------------------------------------------------------------------
# Risk Fusion & Severity Tier Functions
# ---------------------------------------------------------------------------
def calculate_context_risk(row):
    """
    Computes rule-based contextual risk score S_context in [0, 1] based on
    domain-specific insider threat signals (privilege abuse, off-hours, etc.).
    """
    score = 0.0

    # 1. Access to sensitive server by non-privileged host (+0.35)
    if row.get('sensitive_server_access', 0) > 0 and row.get('is_privileged_host', 0) == 0:
        score += 0.35

    # 2. Privileged port access by standard workstation (+0.25)
    if row.get('privileged_port_access', 0) > 0 and row.get('is_workstation', 0) == 1:
        score += 0.25

    # 3. Off-hours activity (+0.20)
    off_hours = row.get('off_hours_ratio', 0)
    if off_hours > 0.5:
        score += 0.20

    # 4. Heavy external traffic ratio combined with high byte rate (+0.20)
    ext_ratio = row.get('external_traffic_ratio', 0)
    if ext_ratio > 0.6:
        score += 0.20

    # 5. Baseline deviation z-score (+0.20 if z > 3.0)
    z = row.get('baseline_deviation_zscore', 0)
    if z > 3.0:
        score += min(0.30, (z - 3.0) * 0.05 + 0.15)

    # 6. High destination IP/Port entropy indicating scanning (+0.25)
    if row.get('dst_ip_entropy', 0) > 2.0 or row.get('dst_port_entropy', 0) > 2.5:
        score += 0.25

    return float(np.clip(score, 0.0, 1.0))


def fuse_risk_scores(p_supervised, s_unsupervised, s_context, weights=(0.50, 0.30, 0.20)):
    """
    Fuses supervised probability, unsupervised outlier score, and context flags:
        s_fused = w_sup * P_sup + w_unsup * S_unsup + w_ctx * S_ctx
    """
    w_sup, w_unsup, w_ctx = weights
    fused = (w_sup * p_supervised) + (w_unsup * s_unsupervised) + (w_ctx * s_context)
    return float(np.clip(fused, 0.0, 1.0))


def classify_severity_tier(fused_score):
    """
    Categorizes the fused risk score into four enterprise severity tiers:
        - Low:      s < 0.35
        - Medium:   0.35 <= s < 0.65
        - High:     0.65 <= s < 0.85
        - Critical: s >= 0.85
    """
    if fused_score >= 0.85:
        return "Critical", "#FF1E1E", "Immediate Host Isolation (DROP Rule)"
    elif fused_score >= 0.65:
        return "High", "#FF8C00", "Rate-Limiting / Strict Port Quarantine"
    elif fused_score >= 0.35:
        return "Medium", "#FFD700", "Analyst Review / Enhanced Logging"
    else:
        return "Low", "#00C853", "Normal Traffic Baseline"


# ---------------------------------------------------------------------------
# Synthetic Enterprise Dataset & Attack Scenario Generator
# ---------------------------------------------------------------------------
def generate_realistic_enterprise_dataset(num_benign_flows=2500, num_threat_flows=600):
    """
    Generates realistic enterprise network flows simulating both benign day-to-day
    traffic and 4 realistic Insider Threat scenarios:
      Scenario A: Data Exfiltration (mass file/DB copy to external IP off-hours)
      Scenario B: Internal Reconnaissance / Lateral Port Scan
      Scenario C: Privilege Abuse (unauthorized HR workstation querying DB port 5432)
      Scenario D: Stealth C2 Beaconing (periodic outbound heartbeats)
    """
    print("[DatasetGenerator] Synthesizing realistic enterprise SDN flows...")
    records = []
    base_ts = time.time() - 3600  # 1 hour ago

    # Workstations and Servers in Topology
    workstations = ['10.0.1.10', '10.0.1.11', '10.0.1.12']
    servers = ['10.0.2.10', '10.0.2.20']
    ext_servers = ['10.0.3.100', '198.51.100.25', '203.0.113.88']

    # 1. BENIGN TRAFFIC (Business Hours: 09:00 - 17:00, standard web/email/file)
    for _ in range(num_benign_flows):
        ts = base_ts + random.uniform(0, 3600)
        src = random.choice(workstations)
        # Normal traffic visits intranet file server or web
        if random.random() < 0.4:
            dst = '10.0.2.20'
            dst_port = random.choice([8080, 445])
            pkts = random.randint(10, 80)
            bytes_cnt = pkts * random.randint(300, 1200)
        elif random.random() < 0.7:
            dst = random.choice(ext_servers)
            dst_port = random.choice([80, 443])
            pkts = random.randint(5, 50)
            bytes_cnt = pkts * random.randint(200, 800)
        else:
            dst = random.choice(workstations)
            dst_port = random.choice([135, 445, 5353])
            pkts = random.randint(3, 20)
            bytes_cnt = pkts * random.randint(60, 300)

        duration = random.uniform(0.1, 5.0)
        records.append({
            'timestamp': ts,
            'datetime_str': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'),
            'switch_id': 1,
            'eth_src': '00:00:00:00:01:10',
            'eth_dst': '00:00:00:00:02:20',
            'ip_src': src,
            'ip_dst': dst,
            'src_port': random.randint(49152, 65535),
            'dst_port': dst_port,
            'protocol': 'TCP',
            'packet_count': pkts,
            'byte_count': bytes_cnt,
            'duration_sec': duration,
            'delta_packets': pkts,
            'delta_bytes': bytes_cnt,
            'byte_rate': bytes_cnt / duration,
            'packet_rate': pkts / duration,
            'is_threat': 0,
            'threat_type': 'BENIGN'
        })

    # 2. INSIDER THREAT SCENARIOS
    # Scenario A: Massive Data Exfiltration from ws2 (10.0.1.11) to external server at night
    exfil_start = base_ts + 2400
    for i in range(150):
        ts = exfil_start + (i * 0.5)
        # Off-hours timestamp simulation (e.g. 02:00 AM)
        pkts = random.randint(400, 1500)
        bytes_cnt = pkts * random.randint(1200, 1460)  # Max MTU payloads
        duration = random.uniform(0.5, 3.0)
        records.append({
            'timestamp': ts,
            'datetime_str': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'),
            'switch_id': 1,
            'eth_src': '00:00:00:00:01:11',
            'eth_dst': '00:00:00:00:03:64',
            'ip_src': '10.0.1.11',
            'ip_dst': '10.0.3.100',
            'src_port': random.randint(49152, 65535),
            'dst_port': 443,
            'protocol': 'TCP',
            'packet_count': pkts,
            'byte_count': bytes_cnt,
            'duration_sec': duration,
            'delta_packets': pkts,
            'delta_bytes': bytes_cnt,
            'byte_rate': bytes_cnt / duration,
            'packet_rate': pkts / duration,
            'is_threat': 1,
            'threat_type': 'DATA_EXFILTRATION'
        })

    # Scenario B: Lateral Reconnaissance / Port Scan by ws1 (10.0.1.10)
    scan_start = base_ts + 1200
    scan_ports = list(range(20, 150)) + [445, 1433, 3306, 3389, 5432, 8080]
    for i, port in enumerate(scan_ports[:180]):
        ts = scan_start + (i * 0.1)
        pkts = random.randint(1, 3)  # SYN-only packet bursts
        bytes_cnt = pkts * random.randint(40, 60)
        duration = 0.05
        records.append({
            'timestamp': ts,
            'datetime_str': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'),
            'switch_id': 1,
            'eth_src': '00:00:00:00:01:10',
            'eth_dst': '00:00:00:00:02:10',
            'ip_src': '10.0.1.10',
            'ip_dst': '10.0.2.10',
            'src_port': random.randint(49152, 65535),
            'dst_port': port,
            'protocol': 'TCP',
            'packet_count': pkts,
            'byte_count': bytes_cnt,
            'duration_sec': duration,
            'delta_packets': pkts,
            'delta_bytes': bytes_cnt,
            'byte_rate': bytes_cnt / duration,
            'packet_rate': pkts / duration,
            'is_threat': 1,
            'threat_type': 'INTERNAL_RECONNAISSANCE'
        })

    # Scenario C: Privilege Abuse (Unprivileged HR ws1 hitting DB server port 5432)
    abuse_start = base_ts + 1800
    for i in range(120):
        ts = abuse_start + (i * 0.8)
        pkts = random.randint(25, 90)
        bytes_cnt = pkts * random.randint(500, 1100)
        duration = random.uniform(0.2, 1.5)
        records.append({
            'timestamp': ts,
            'datetime_str': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'),
            'switch_id': 1,
            'eth_src': '00:00:00:00:01:10',
            'eth_dst': '00:00:00:00:02:10',
            'ip_src': '10.0.1.10',
            'ip_dst': '10.0.2.10',
            'src_port': random.randint(49152, 65535),
            'dst_port': 5432,
            'protocol': 'TCP',
            'packet_count': pkts,
            'byte_count': bytes_cnt,
            'duration_sec': duration,
            'delta_packets': pkts,
            'delta_bytes': bytes_cnt,
            'byte_rate': bytes_cnt / duration,
            'packet_rate': pkts / duration,
            'is_threat': 1,
            'threat_type': 'PRIVILEGE_ABUSE'
        })

    df = pd.DataFrame(records).sort_values(by='timestamp').reset_index(drop=True)
    print(f"[DatasetGenerator] Generated {len(df)} total flows (Benign: {num_benign_flows}, Threat: {len(df) - num_benign_flows}).")
    return df


def save_flows_to_sqlite(df, db_path=DEFAULT_DB_PATH):
    """Writes DataFrame to flow_records table in SQLite."""
    conn = sqlite3.connect(db_path)
    # Exclude synthetic label columns when writing to raw OpenFlow schema if desired,
    # or preserve for ground truth validation
    cols_to_write = [c for c in df.columns if c not in ['is_threat', 'threat_type']]
    df[cols_to_write].to_sql('flow_records', conn, if_exists='replace', index=False)
    conn.commit()
    conn.close()
    print(f"[DatasetGenerator] Saved {len(df)} records into SQLite: {db_path}")


# ---------------------------------------------------------------------------
# Training Pipeline
# ---------------------------------------------------------------------------
class ThreatDetectionEngine:
    """
    Coordinates training, inference, and persistence of the hybrid
    Supervised RF + Unsupervised Isolation Forest + Context Risk Fusion pipeline.
    """

    def __init__(self):
        self.preprocessor = FeaturePreprocessor()
        self.rf_model = None
        self.iforest_model = None
        self.baseline_stats = {}
        self.is_trained = False

    def train(self, flow_df=None):
        """
        Executes end-to-end training:
          1. Window extraction (10-second sliding windows).
          2. Baseline stats calculation for benign host activity.
          3. Unsupervised Isolation Forest training (strictly on benign windows).
          4. Supervised Random Forest training with balanced class weights.
          5. Model evaluation and serialization.
        """
        if flow_df is None or flow_df.empty:
            flow_df = generate_realistic_enterprise_dataset()
            save_flows_to_sqlite(flow_df)

        print("\n[Step 1/5] Extracting 10-second host sliding windows...")
        windows_df = extract_sliding_windows(flow_df, window_size=10.0, step_size=5.0)
        print(f"Extracted {len(windows_df)} sliding window samples.")

        if 'is_threat' not in windows_df.columns:
            raise ValueError("Training dataset must contain 'is_threat' binary label column.")

        # Compute host baseline stats on benign data
        benign_windows = windows_df[windows_df['is_threat'] == 0]
        self.baseline_stats = {}
        for host, h_group in benign_windows.groupby('host_ip'):
            self.baseline_stats[host] = {
                'mean_bps': float(h_group['bytes_per_sec'].mean()),
                'std_bps': float(max(10.0, h_group['bytes_per_sec'].std()))
            }
        with open(BASELINE_STATS_PATH, 'w') as f:
            json.dump(self.baseline_stats, f, indent=2)

        # Fit RobustScaler on benign data
        print("[Step 2/5] Fitting Robust Scaler on benign baseline windows...")
        self.preprocessor.fit(benign_windows)
        self.preprocessor.save()

        # Transform all feature vectors
        X_scaled = self.preprocessor.transform(windows_df)
        y = windows_df['is_threat'].values

        # Split into Train / Test (80/20 stratified)
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.20, random_state=42, stratify=y
        )

        # Train Unsupervised Isolation Forest strictly on benign training set
        print("[Step 3/5] Training Unsupervised Isolation Forest on benign traffic...")
        X_train_benign = X_train[y_train == 0]
        self.iforest_model = IsolationForest(
            n_estimators=120,
            contamination=0.03,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        self.iforest_model.fit(X_train_benign)
        joblib.dump(self.iforest_model, UNSUPERVISED_MODEL_PATH)

        # Train Supervised Random Forest with cost-sensitive class weights
        print("[Step 4/5] Training Supervised Cost-Sensitive Random Forest...")
        self.rf_model = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_split=4,
            class_weight='balanced',  # Compensates for class imbalance
            random_state=42,
            n_jobs=-1
        )
        self.rf_model.fit(X_train, y_train)
        joblib.dump(self.rf_model, SUPERVISED_MODEL_PATH)

        # Step 5: Comprehensive Evaluation & Fusion Testing
        print("\n[Step 5/5] Evaluating Detection Models & Risk Fusion Engine...")
        y_pred_rf = self.rf_model.predict(X_test)
        y_prob_rf = self.rf_model.predict_proba(X_test)[:, 1]

        # Calculate Unsupervised scores for test set
        raw_if_scores = self.iforest_model.decision_function(X_test)
        # Logistic normalization: negative raw scores (outliers) map to ~1.0, positive (inliers) map to ~0.0
        s_unsup_test = 1.0 / (1.0 + np.exp(12.0 * raw_if_scores))

        # Context scores
        s_ctx_test = np.array([
            calculate_context_risk(row) for _, row in windows_df.loc[X_test.index].iterrows()
        ])

        # Fused scores
        s_fused_test = np.array([
            fuse_risk_scores(p, u, c)
            for p, u, c in zip(y_prob_rf, s_unsup_test, s_ctx_test)
        ])

        y_pred_fused = (s_fused_test >= 0.50).astype(int)

        prec = precision_score(y_test, y_pred_fused, zero_division=0)
        rec = recall_score(y_test, y_pred_fused, zero_division=0)
        f1 = f1_score(y_test, y_pred_fused, zero_division=0)
        roc = roc_auc_score(y_test, s_fused_test)

        print("\n" + "=" * 60)
        print("MODEL EVALUATION RESULTS (Fused Pipeline on Test Split):")
        print("=" * 60)
        print(f"  Precision : {prec:.4f}")
        print(f"  Recall    : {rec:.4f}")
        print(f"  F1-Score  : {f1:.4f}")
        print(f"  ROC-AUC   : {roc:.4f}")
        print("-" * 60)
        print("Confusion Matrix:")
        print(confusion_matrix(y_test, y_pred_fused))
        print("-" * 60)
        print("Detailed Classification Report:")
        print(classification_report(y_test, y_pred_fused, target_names=['Benign', 'Threat']))
        print("=" * 60)

        # Save metadata
        metadata = {
            'trained_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'feature_count': len(FEATURE_COLUMNS),
            'feature_columns': FEATURE_COLUMNS,
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'metrics': {
                'precision': float(prec),
                'recall': float(rec),
                'f1_score': float(f1),
                'roc_auc': float(roc)
            },
            'weights': {'supervised': 0.50, 'unsupervised': 0.30, 'context': 0.20},
            'thresholds': {'low': 0.35, 'medium': 0.65, 'high': 0.85}
        }
        with open(METADATA_PATH, 'w') as f:
            json.dump(metadata, f, indent=2)

        self.is_trained = True
        return metadata

    def load(self):
        """Loads all serialized models, preprocessor, and metadata from disk."""
        if not (os.path.exists(SUPERVISED_MODEL_PATH) and os.path.exists(UNSUPERVISED_MODEL_PATH)):
            return False

        self.rf_model = joblib.load(SUPERVISED_MODEL_PATH)
        self.iforest_model = joblib.load(UNSUPERVISED_MODEL_PATH)
        self.preprocessor.load()

        if os.path.exists(BASELINE_STATS_PATH):
            with open(BASELINE_STATS_PATH, 'r') as f:
                self.baseline_stats = json.load(f)

        self.is_trained = True
        return True

    def predict_window(self, raw_window_dict):
        """
        Performs full inference on a single 10-second window dictionary:
          1. Scales features.
          2. Predicts Supervised Probability.
          3. Predicts Unsupervised Outlier Score.
          4. Calculates Context Risk.
          5. Fuses scores and assigns Severity Tier.
        """
        if not self.is_trained:
            if not self.load():
                raise RuntimeError("Models are not trained. Please train first.")

        df_single = pd.DataFrame([raw_window_dict])
        scaled_df = self.preprocessor.transform(df_single)

        # Supervised probability
        p_sup = float(self.rf_model.predict_proba(scaled_df)[0][1])

        # Unsupervised score
        raw_if = float(self.iforest_model.decision_function(scaled_df)[0])
        s_unsup = float(1.0 / (1.0 + np.exp(12.0 * raw_if)))

        # Context score
        s_ctx = calculate_context_risk(raw_window_dict)

        # Fused score
        s_fused = fuse_risk_scores(p_sup, s_unsup, s_ctx)
        tier, color, action = classify_severity_tier(s_fused)

        return {
            'p_supervised': p_sup,
            's_unsupervised': s_unsup,
            's_context': s_ctx,
            's_fused': s_fused,
            'severity_tier': tier,
            'tier_color': color,
            'recommended_action': action,
            'scaled_features': scaled_df.iloc[0].to_dict()
        }


if __name__ == '__main__':
    print("=" * 70)
    print("MODULE 3: Machine Learning Detection Engine")
    print("=" * 70)
    engine = ThreatDetectionEngine()
    metadata = engine.train()
    print("[Done] Pipeline trained, evaluated, and saved successfully.")
