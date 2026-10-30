#!/usr/bin/env python3
"""
=============================================================================
EXTENDED CAPABILITY: MITRE ATT&CK Mapping & Threat Intelligence Engine
Project: Explainable AI-Based Insider Threat Detection in SDN using SHAP/LIME
File: mitre_mapper.py
=============================================================================
Description:
    Maps network behavioral anomaly signatures and top SHAP feature attributions
    to the industry-standard MITRE ATT&CK for Enterprise framework.
    Provides formal TTPs (Tactics, Techniques, and Procedures), mitigation guidance,
    and forensic evidence correlation.
"""

MITRE_TECHNIQUES = {
    'DATA_EXFILTRATION': {
        'tactic': 'Exfiltration (TA0010)',
        'technique_id': 'T1048.003',
        'technique_name': 'Exfiltration Over Unencrypted/Encrypted Non-C2 Protocol',
        'description': 'Malicious insider transfers sensitive enterprise intellectual property or databases to an external cloud endpoint via high-throughput bursts.',
        'primary_features': ['bytes_per_sec', 'total_bytes', 'off_hours_ratio', 'external_traffic_ratio'],
        'detection_criteria': 'Throughput z-score > 3.5 combined with off-hours activity and external gateway destination.',
        'recommended_sdn_action': 'HARD_ISOLATE_DROP',
        'nist_control': 'NIST SP 800-53 SC-7 (Boundary Protection) & AC-4 (Information Flow Enforcement)'
    },
    'INTERNAL_RECONNAISSANCE': {
        'tactic': 'Discovery (TA0007)',
        'technique_id': 'T1046',
        'technique_name': 'Network Service Discovery / Port Scanning',
        'description': 'Insider actively scans internal subnet ranges and sensitive server ports to identify exploitable listening services and lateral movement vectors.',
        'primary_features': ['dst_port_entropy', 'unique_dst_ports', 'failed_rare_conn_ratio', 'packets_per_sec'],
        'detection_criteria': 'High destination port entropy (> 2.0) with low packet counts per flow (SYN-only probes).',
        'recommended_sdn_action': 'RATE_LIMIT_QUARANTINE',
        'nist_control': 'NIST SP 800-53 CA-7 (Continuous Monitoring) & SI-4 (Information System Monitoring)'
    },
    'PRIVILEGE_ABUSE': {
        'tactic': 'Privilege Escalation / Lateral Movement (TA0004 / TA0008)',
        'technique_id': 'T1078.002',
        'technique_name': 'Valid Accounts: Domain / Database Abuse',
        'description': 'Standard employee workstation accesses mission-critical database (port 5432) or file repository outside legitimate departmental business scope.',
        'primary_features': ['sensitive_server_access', 'privileged_port_access', 'is_privileged_host', 'bytes_per_flow'],
        'detection_criteria': 'Direct connection to protected DB server (10.0.2.10:5432) originated by unprivileged host.',
        'recommended_sdn_action': 'SURGICAL_PORT_BLOCK',
        'nist_control': 'NIST SP 800-53 AC-6 (Least Privilege) & AC-3 (Access Enforcement)'
    },
    'STEALTH_BEACONING': {
        'tactic': 'Command and Control (TA0011)',
        'technique_id': 'T1071.001',
        'technique_name': 'Application Layer Protocol: Web Protocols',
        'description': 'Automated low-frequency periodic beaconing to unauthorized shadow IT or external server at regular intervals.',
        'primary_features': ['inter_arrival_time_std', 'flows_per_min', 'off_hours_ratio'],
        'detection_criteria': 'Extremely low inter-arrival variance (< 0.05) with regular periodic external callbacks.',
        'recommended_sdn_action': 'DECOY_HONEYNET_REDIRECT',
        'nist_control': 'NIST SP 800-53 SC-5 (Denial of Service Protection) & SI-4'
    }
}


def map_threat_to_mitre(threat_type_or_features):
    """
    Infers the MITRE ATT&CK technique based on feature signatures or threat label.
    """
    if isinstance(threat_type_or_features, str) and threat_type_or_features in MITRE_TECHNIQUES:
        return MITRE_TECHNIQUES[threat_type_or_features]

    # Rule-based inference from feature dictionary
    f = threat_type_or_features if isinstance(threat_type_or_features, dict) else {}

    if f.get('sensitive_server_access', 0) > 0 or f.get('privileged_port_access', 0) > 0:
        return MITRE_TECHNIQUES['PRIVILEGE_ABUSE']
    elif f.get('dst_port_entropy', 0) > 1.8 or f.get('unique_dst_ports', 0) > 10:
        return MITRE_TECHNIQUES['INTERNAL_RECONNAISSANCE']
    elif f.get('bytes_per_sec', 0) > 100000 or f.get('baseline_deviation_zscore', 0) > 3.0:
        return MITRE_TECHNIQUES['DATA_EXFILTRATION']
    else:
        return MITRE_TECHNIQUES['DATA_EXFILTRATION']
