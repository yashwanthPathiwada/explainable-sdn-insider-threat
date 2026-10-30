#!/usr/bin/env python3
"""
=============================================================================
MODULE 2: Feature Engineering & Preprocessing Pipeline
Project: Explainable AI-Based Insider Threat Detection in SDN using SHAP/LIME
File: feature_engineering.py
=============================================================================
Description:
    Aggregates raw OpenFlow statistics from SQLite/DataFrame into 10-second
    host-level sliding windows. Computes 5 behavioral feature categories:
      1. Volume Features: Bytes/flow, packets/flow, mean packet size.
      2. Rate Features: Bytes/sec, packets/sec, flows/min.
      3. Temporal Features: Mean flow duration, inter-arrival time, off-hours ratio.
      4. Behavior Features: Unique dst IPs/ports, Shannon entropy, connection frequency, rare/failed ratio.
      5. Context Features: Host role indicators, baseline deviation (z-scores), account status flags.

    Provides rigorous data cleaning, missing value imputation, and robust scaling
    without introducing data leakage.
"""

import os
import math
import sqlite3
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from collections import Counter
from sklearn.preprocessing import RobustScaler
from sklearn.impute import SimpleImputer

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

DEFAULT_DB_PATH = os.path.join(DATA_DIR, 'flow_records.db')
SCALER_PATH = os.path.join(MODEL_DIR, 'robust_scaler.pkl')
IMPUTER_PATH = os.path.join(MODEL_DIR, 'feature_imputer.pkl')
BASELINE_STATS_PATH = os.path.join(MODEL_DIR, 'baseline_stats.json')

# Standard Enterprise Asset Mapping for Context Feature Extraction
ASSET_ROLES = {
    '10.0.1.10': {'role': 'HR_USER', 'is_workstation': 1, 'is_server': 0, 'privileged': 0},
    '10.0.1.11': {'role': 'FIN_USER', 'is_workstation': 1, 'is_server': 0, 'privileged': 0},
    '10.0.1.12': {'role': 'IT_ADMIN', 'is_workstation': 1, 'is_server': 0, 'privileged': 1},
    '10.0.2.10': {'role': 'DB_SERVER', 'is_workstation': 0, 'is_server': 1, 'privileged': 1},
    '10.0.2.20': {'role': 'FILE_SERVER', 'is_workstation': 0, 'is_server': 1, 'privileged': 1},
    '10.0.3.1':  {'role': 'GATEWAY', 'is_workstation': 0, 'is_server': 0, 'privileged': 0},
    '10.0.3.100': {'role': 'EXT_SERVER', 'is_workstation': 0, 'is_server': 0, 'privileged': 0}
}

SENSITIVE_SERVERS = {'10.0.2.10', '10.0.2.20'}
SENSITIVE_PORTS = {5432, 3306, 445, 2049, 22}

# Exact feature ordering used for training and model inference
FEATURE_COLUMNS = [
    # 1. Volume Features
    'bytes_per_flow',
    'packets_per_flow',
    'mean_packet_size',
    'total_bytes',
    'total_packets',
    # 2. Rate Features
    'bytes_per_sec',
    'packets_per_sec',
    'flows_per_min',
    # 3. Temporal Features
    'mean_flow_duration',
    'inter_arrival_time_mean',
    'inter_arrival_time_std',
    'off_hours_ratio',
    # 4. Behavior Features
    'unique_dst_ips',
    'unique_dst_ports',
    'dst_ip_entropy',
    'dst_port_entropy',
    'connection_frequency',
    'failed_rare_conn_ratio',
    # 5. Context Features
    'is_workstation',
    'is_server',
    'is_privileged_host',
    'baseline_deviation_zscore',
    'sensitive_server_access',
    'privileged_port_access',
    'external_traffic_ratio'
]


def shannon_entropy(items):
    """
    Computes Shannon Entropy: H(X) = -sum(p_i * log2(p_i)).
    Quantifies dispersion across destination IPs or target ports.
    """
    if not items or len(items) == 0:
        return 0.0
    total = len(items)
    counts = Counter(items)
    ent = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            ent -= p * math.log2(p)
    return float(ent)


def compute_host_window_features(window_df, host_ip, window_duration=10.0, baseline_stats=None):
    """
    Computes the 5 behavioral feature groups for a single host during a 10-second window.
    """
    feat = {}
    num_flows = len(window_df)

    if num_flows == 0:
        return None

    # Sort flows chronologically
    sorted_df = window_df.sort_values(by='timestamp')

    # ---------------------------------------------------------
    # 1. VOLUME FEATURES
    # ---------------------------------------------------------
    total_bytes = float(window_df['byte_count'].sum())
    total_packets = float(window_df['packet_count'].sum())

    feat['total_bytes'] = total_bytes
    feat['total_packets'] = total_packets
    feat['bytes_per_flow'] = total_bytes / max(1, num_flows)
    feat['packets_per_flow'] = total_packets / max(1, num_flows)
    feat['mean_packet_size'] = total_bytes / max(1.0, total_packets)

    # ---------------------------------------------------------
    # 2. RATE FEATURES
    # ---------------------------------------------------------
    eff_duration = max(1.0, window_duration)
    feat['bytes_per_sec'] = total_bytes / eff_duration
    feat['packets_per_sec'] = total_packets / eff_duration
    feat['flows_per_min'] = num_flows * (60.0 / eff_duration)

    # ---------------------------------------------------------
    # 3. TEMPORAL FEATURES
    # ---------------------------------------------------------
    feat['mean_flow_duration'] = float(window_df['duration_sec'].mean()) if 'duration_sec' in window_df else 0.0

    # Inter-arrival times between consecutive flows
    if num_flows > 1:
        timestamps = sorted_df['timestamp'].values
        diffs = np.diff(timestamps)
        feat['inter_arrival_time_mean'] = float(np.mean(diffs))
        feat['inter_arrival_time_std'] = float(np.std(diffs))
    else:
        feat['inter_arrival_time_mean'] = float(window_duration)
        feat['inter_arrival_time_std'] = 0.0

    # Off-hours calculation (Standard Enterprise business hours: 08:00 - 18:00 Mon-Fri)
    def is_off_hours_ts(ts):
        dt = datetime.fromtimestamp(ts)
        # 5 = Saturday, 6 = Sunday
        if dt.weekday() >= 5:
            return 1.0
        return 1.0 if (dt.hour < 8 or dt.hour >= 18) else 0.0

    off_hours_flags = [is_off_hours_ts(ts) for ts in window_df['timestamp']]
    feat['off_hours_ratio'] = float(np.mean(off_hours_flags)) if off_hours_flags else 0.0

    # ---------------------------------------------------------
    # 4. BEHAVIOR FEATURES
    # ---------------------------------------------------------
    dst_ips = [str(x) for x in window_df['ip_dst'].dropna()]
    dst_ports = [int(x) for x in window_df['dst_port'].dropna()]

    feat['unique_dst_ips'] = float(len(set(dst_ips)))
    feat['unique_dst_ports'] = float(len(set(dst_ports)))
    feat['dst_ip_entropy'] = shannon_entropy(dst_ips)
    feat['dst_port_entropy'] = shannon_entropy(dst_ports)
    feat['connection_frequency'] = float(num_flows / eff_duration)

    # Failed / Rare connection ratio (e.g. syn probes with packets <= 3 or uncommon high ports)
    rare_or_failed = 0
    for _, row in window_df.iterrows():
        p_cnt = row.get('packet_count', 0)
        p_dst = row.get('dst_port', 0)
        # Port scan probes or failed connection bursts typically have <= 3 packets
        if p_cnt <= 3 or (p_dst > 1024 and p_dst not in {5432, 8080, 8443, 3306}):
            rare_or_failed += 1
    feat['failed_rare_conn_ratio'] = float(rare_or_failed / max(1, num_flows))

    # ---------------------------------------------------------
    # 5. CONTEXT FEATURES
    # ---------------------------------------------------------
    role_meta = ASSET_ROLES.get(host_ip, {'role': 'UNKNOWN', 'is_workstation': 1, 'is_server': 0, 'privileged': 0})
    feat['is_workstation'] = float(role_meta['is_workstation'])
    feat['is_server'] = float(role_meta['is_server'])
    feat['is_privileged_host'] = float(role_meta['privileged'])

    # Sensitive server access flag (e.g. workstation hitting database server 10.0.2.10)
    has_sensitive_dst = any(ip in SENSITIVE_SERVERS for ip in dst_ips)
    feat['sensitive_server_access'] = 1.0 if has_sensitive_dst else 0.0

    # Privileged port access flag
    has_sensitive_port = any(port in SENSITIVE_PORTS for port in dst_ports)
    feat['privileged_port_access'] = 1.0 if has_sensitive_port else 0.0

    # External traffic ratio
    ext_cnt = sum(1 for ip in dst_ips if ip.startswith('10.0.3.') or not ip.startswith('10.0.'))
    feat['external_traffic_ratio'] = float(ext_cnt / max(1, num_flows))

    # Baseline deviation z-score: Z = (current_bytes_per_sec - mu) / sigma
    if baseline_stats and host_ip in baseline_stats:
        b_mu = baseline_stats[host_ip].get('mean_bps', 1000.0)
        b_sigma = baseline_stats[host_ip].get('std_bps', 500.0)
        feat['baseline_deviation_zscore'] = float((feat['bytes_per_sec'] - b_mu) / max(1.0, b_sigma))
    else:
        # Default baseline estimation
        feat['baseline_deviation_zscore'] = float(max(0.0, (feat['bytes_per_sec'] - 1500.0) / 1000.0))

    return feat


def extract_sliding_windows(flow_df, window_size=10.0, step_size=5.0, baseline_stats=None):
    """
    Partitions the raw flow DataFrame into 10-second sliding windows per source IP.
    Returns a DataFrame where each row is an engineered feature vector for one window.
    """
    if flow_df.empty:
        return pd.DataFrame(columns=['window_start', 'window_end', 'host_ip'] + FEATURE_COLUMNS)

    flow_df = flow_df.sort_values(by='timestamp').copy()
    min_time = flow_df['timestamp'].min()
    max_time = flow_df['timestamp'].max()

    feature_rows = []

    # Slide window over time range
    current_start = min_time
    while current_start <= max_time:
        current_end = current_start + window_size
        window_mask = (flow_df['timestamp'] >= current_start) & (flow_df['timestamp'] < current_end)
        sub_df = flow_df[window_mask]

        if not sub_df.empty:
            # Group by source host
            for host_ip, host_group in sub_df.groupby('ip_src'):
                if not host_ip or pd.isna(host_ip):
                    continue
                features = compute_host_window_features(
                    host_group,
                    str(host_ip),
                    window_duration=window_size,
                    baseline_stats=baseline_stats
                )
                if features:
                    features['window_start'] = current_start
                    features['window_end'] = current_end
                    features['host_ip'] = str(host_ip)
                    # Preserve label if present in raw logs
                    if 'is_threat' in host_group.columns:
                        features['is_threat'] = int(host_group['is_threat'].max())
                    if 'threat_type' in host_group.columns:
                        features['threat_type'] = str(host_group['threat_type'].iloc[0])
                    feature_rows.append(features)

        current_start += step_size

    if not feature_rows:
        return pd.DataFrame(columns=['window_start', 'window_end', 'host_ip'] + FEATURE_COLUMNS)

    return pd.DataFrame(feature_rows)


class FeaturePreprocessor:
    """
    Robust Preprocessing Pipeline:
      - Imputes missing/infinite values without leakage
      - Fits a RobustScaler exclusively on benign training data
      - Serializes and deserializes artifacts
    """

    def __init__(self):
        self.imputer = SimpleImputer(strategy='median')
        self.scaler = RobustScaler(with_centering=True, with_scaling=True, quantile_range=(25.0, 75.0))
        self.is_fitted = False

    def clean_features(self, df):
        """Sanitizes DataFrame by removing infinities and ensuring correct types."""
        feature_df = df[FEATURE_COLUMNS].copy()
        feature_df.replace([np.inf, -np.inf], np.nan, inplace=True)
        return feature_df

    def fit(self, benign_df):
        """Fits imputer and scaler strictly on benign baseline samples."""
        clean_df = self.clean_features(benign_df)
        imputed_array = self.imputer.fit_transform(clean_df)
        self.scaler.fit(imputed_array)
        self.is_fitted = True
        return self

    def transform(self, df):
        """Transforms incoming sliding windows using the fitted preprocessor."""
        clean_df = self.clean_features(df)
        if not self.is_fitted:
            raise RuntimeError("FeaturePreprocessor must be fitted before transform.")
        imputed_array = self.imputer.transform(clean_df)
        scaled_array = self.scaler.transform(imputed_array)
        return pd.DataFrame(scaled_array, columns=FEATURE_COLUMNS, index=df.index)

    def fit_transform(self, benign_df):
        self.fit(benign_df)
        return self.transform(benign_df)

    def save(self, scaler_path=SCALER_PATH, imputer_path=IMPUTER_PATH):
        joblib.dump(self.scaler, scaler_path)
        joblib.dump(self.imputer, imputer_path)
        print(f"[FeaturePreprocessor] Saved scaler to {scaler_path}")

    def load(self, scaler_path=SCALER_PATH, imputer_path=IMPUTER_PATH):
        if os.path.exists(scaler_path) and os.path.exists(imputer_path):
            self.scaler = joblib.load(scaler_path)
            self.imputer = joblib.load(imputer_path)
            self.is_fitted = True
            return True
        return False


def load_flows_from_db(db_path=DEFAULT_DB_PATH, limit=None):
    """Queries flow records from SQLite database."""
    if not os.path.exists(db_path):
        return pd.DataFrame()
    conn = sqlite3.connect(db_path)
    query = "SELECT * FROM flow_records ORDER BY timestamp ASC"
    if limit:
        query += f" LIMIT {limit}"
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df


if __name__ == '__main__':
    print("=" * 70)
    print("MODULE 2: Feature Engineering & Preprocessing Pipeline")
    print("=" * 70)
    print(f"Features Configured : {len(FEATURE_COLUMNS)}")
    for i, col in enumerate(FEATURE_COLUMNS, 1):
        print(f"  {i:2d}. {col}")
    print("-" * 70)

    # Test with dummy data
    test_flows = pd.DataFrame([
        {'timestamp': 100.0, 'ip_src': '10.0.1.10', 'ip_dst': '10.0.2.10', 'src_port': 49152, 'dst_port': 5432,
         'protocol': 'TCP', 'packet_count': 12, 'byte_count': 1420, 'duration_sec': 1.2},
        {'timestamp': 102.5, 'ip_src': '10.0.1.10', 'ip_dst': '10.0.2.10', 'src_port': 49153, 'dst_port': 5432,
         'protocol': 'TCP', 'packet_count': 15, 'byte_count': 2300, 'duration_sec': 2.1},
        {'timestamp': 105.0, 'ip_src': '10.0.1.11', 'ip_dst': '10.0.3.100', 'src_port': 49200, 'dst_port': 443,
         'protocol': 'TCP', 'packet_count': 500, 'byte_count': 750000, 'duration_sec': 4.5}
    ])

    windows = extract_sliding_windows(test_flows, window_size=10.0, step_size=5.0)
    print(f"Extracted {len(windows)} sliding windows.")
    preprocessor = FeaturePreprocessor()
    preprocessor.fit(windows)
    scaled = preprocessor.transform(windows)
    print("Scaled feature preview (first row):")
    print(scaled.iloc[0].to_dict())
