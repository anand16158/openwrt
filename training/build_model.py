#!/usr/bin/env python3
"""
All-in-one: generate synthetic data → train XGBoost → export to C code.

The generated C file implements the tc_model.h interface:
  - tc_model_predict(features, output) → predicted class index
  - tc_model_available() → 1

Usage:
    cd training/
    pip install -r requirements.txt

    # Train on synthetic data (default):
    python build_model.py

    # Train on real data captured from the router:
    python build_model.py --input real_data.csv

    # Combine real + synthetic data:
    python build_model.py --input real_data.csv --augment

    # The script writes tc_model_xgb.c into ../package/.../src/
    # which replaces tc_model_stub.c at link time.
"""

import argparse
import csv
import json
import math
import os
import random
import sys

import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score

FEATURE_NAMES = [
    "flow_duration_sec", "total_fwd_packets", "total_bwd_packets",
    "total_fwd_bytes", "total_bwd_bytes", "fwd_bwd_bytes_ratio",
    "avg_packet_size", "std_packet_size", "avg_iat_usec",
    "std_iat_usec", "min_packet_size", "max_packet_size",
    "packets_per_second", "bytes_per_second", "fwd_pkt_ratio",
    "avg_fwd_pkt_size", "avg_bwd_pkt_size", "tcp_flags_or",
    "syn_count", "protocol",
]

CLASS_NAMES = [
    "unknown", "video", "gaming", "social",
    "browsing", "download", "voip", "other",
]

N_FEATURES = 20
N_CLASSES = 8

SRC_DIR = os.path.join(
    os.path.dirname(__file__), "..",
    "package", "network", "services", "traffic-classifier", "src"
)

PROFILES = {
    "unknown": {
        "duration": (8.0, 6.0),
        "avg_pkt_size": (400.0, 300.0),
        "pkt_per_sec": (15.0, 12.0),
        "bytes_per_sec": (20000.0, 18000.0),
        "fwd_ratio": (0.45, 0.25),
        "proto": 6,
        "std_pkt_size": (300.0, 150.0),
        "avg_iat": (80000.0, 50000.0),
    },
    "video": {
        "duration": (30.0, 20.0),
        "avg_pkt_size": (1100.0, 200.0),
        "pkt_per_sec": (80.0, 30.0),
        "bytes_per_sec": (500000.0, 200000.0),
        "fwd_ratio": (0.08, 0.04),
        "proto": 6,
        "std_pkt_size": (400.0, 100.0),
        "avg_iat": (12000.0, 5000.0),
    },
    "gaming": {
        "duration": (120.0, 60.0),
        "avg_pkt_size": (120.0, 50.0),
        "pkt_per_sec": (60.0, 20.0),
        "bytes_per_sec": (15000.0, 8000.0),
        "fwd_ratio": (0.48, 0.08),
        "proto": 17,
        "std_pkt_size": (60.0, 30.0),
        "avg_iat": (16000.0, 5000.0),
    },
    "social": {
        "duration": (5.0, 3.0),
        "avg_pkt_size": (450.0, 150.0),
        "pkt_per_sec": (25.0, 15.0),
        "bytes_per_sec": (30000.0, 20000.0),
        "fwd_ratio": (0.35, 0.1),
        "proto": 6,
        "std_pkt_size": (350.0, 100.0),
        "avg_iat": (40000.0, 20000.0),
    },
    "browsing": {
        "duration": (3.0, 2.0),
        "avg_pkt_size": (600.0, 200.0),
        "pkt_per_sec": (30.0, 20.0),
        "bytes_per_sec": (50000.0, 30000.0),
        "fwd_ratio": (0.3, 0.1),
        "proto": 6,
        "std_pkt_size": (450.0, 150.0),
        "avg_iat": (30000.0, 15000.0),
    },
    "download": {
        "duration": (60.0, 40.0),
        "avg_pkt_size": (1350.0, 100.0),
        "pkt_per_sec": (500.0, 200.0),
        "bytes_per_sec": (2000000.0, 1000000.0),
        "fwd_ratio": (0.03, 0.02),
        "proto": 6,
        "std_pkt_size": (200.0, 100.0),
        "avg_iat": (2000.0, 1000.0),
    },
    "voip": {
        "duration": (180.0, 120.0),
        "avg_pkt_size": (180.0, 40.0),
        "pkt_per_sec": (50.0, 10.0),
        "bytes_per_sec": (12000.0, 4000.0),
        "fwd_ratio": (0.50, 0.05),
        "proto": 17,
        "std_pkt_size": (30.0, 15.0),
        "avg_iat": (20000.0, 2000.0),
    },
    "other": {
        "duration": (10.0, 8.0),
        "avg_pkt_size": (300.0, 200.0),
        "pkt_per_sec": (10.0, 8.0),
        "bytes_per_sec": (8000.0, 6000.0),
        "fwd_ratio": (0.4, 0.2),
        "proto": 6,
        "std_pkt_size": (250.0, 100.0),
        "avg_iat": (100000.0, 50000.0),
    },
}


def clamp(val, lo, hi):
    return max(lo, min(hi, val))


def sample_flow(class_name):
    p = PROFILES[class_name]
    duration = clamp(np.random.normal(*p["duration"]), 0.1, 600.0)
    avg_pkt = clamp(np.random.normal(*p["avg_pkt_size"]), 40.0, 1500.0)
    pps = clamp(np.random.normal(*p["pkt_per_sec"]), 1.0, 2000.0)
    bps = clamp(np.random.normal(*p["bytes_per_sec"]), 100.0, 1e7)
    fwd_ratio = clamp(np.random.normal(*p["fwd_ratio"]), 0.01, 0.99)

    total_pkts = max(10, int(pps * duration))
    fwd_pkts = max(1, int(total_pkts * fwd_ratio))
    bwd_pkts = max(1, total_pkts - fwd_pkts)
    total_bytes = max(1000, int(bps * duration))
    fwd_bytes = max(100, int(total_bytes * fwd_ratio))
    bwd_bytes = max(100, total_bytes - fwd_bytes)
    byte_ratio = fwd_bytes / bwd_bytes if bwd_bytes > 0 else float(fwd_bytes)

    std_pkt = clamp(np.random.normal(*p["std_pkt_size"]), 0.0, 800.0)
    avg_iat = clamp(np.random.normal(*p["avg_iat"]), 100.0, 500000.0)
    std_iat = clamp(avg_iat * np.random.uniform(0.3, 1.5), 100.0, 500000.0)
    min_pkt = max(40, int(avg_pkt - 2 * std_pkt))
    max_pkt = min(1500, int(avg_pkt + 2 * std_pkt))
    avg_fwd_pkt = fwd_bytes / fwd_pkts if fwd_pkts > 0 else 0
    avg_bwd_pkt = bwd_bytes / bwd_pkts if bwd_pkts > 0 else 0
    tcp_flags = 0x18 if p["proto"] == 6 else 0
    syn_count = 1 if p["proto"] == 6 else 0

    noise = np.random.normal(0, 0.05, N_FEATURES)
    features = [
        duration, float(fwd_pkts), float(bwd_pkts),
        float(fwd_bytes), float(bwd_bytes), byte_ratio,
        avg_pkt, std_pkt, avg_iat, std_iat,
        float(min_pkt), float(max_pkt), pps, bps,
        fwd_ratio, avg_fwd_pkt, avg_bwd_pkt,
        float(tcp_flags), float(syn_count), float(p["proto"]),
    ]
    return [max(0.0, f * (1 + noise[i])) for i, f in enumerate(features)]


# ── Step 1: Generate synthetic data ──────────────────────────────────

def generate_data(n_samples=10000, seed=42):
    np.random.seed(seed)
    random.seed(seed)

    classes = list(CLASS_NAMES)
    per_class = n_samples // len(classes)
    label_map = {name: i for i, name in enumerate(CLASS_NAMES)}

    X_list, y_list = [], []
    for cls in classes:
        for _ in range(per_class):
            X_list.append(sample_flow(cls))
            y_list.append(label_map[cls])

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)

    perm = np.random.permutation(len(X))
    return X[perm], y[perm]


# ── Step 2: Train XGBoost ────────────────────────────────────────────

def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=N_CLASSES,
        eval_metric="mlogloss",
        use_label_encoder=False,
        tree_method="hist",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    present = sorted(set(y_test) | set(y_pred))
    names = [CLASS_NAMES[i] if i < len(CLASS_NAMES) else f"c{i}" for i in present]

    print(f"\n{'='*60}")
    print(f"  Accuracy:      {acc:.4f}")
    print(f"  F1 (weighted): {f1:.4f}")
    print(f"{'='*60}")
    print(classification_report(
        y_test, y_pred, labels=present, target_names=names, zero_division=0
    ))

    importance = model.feature_importances_
    top = np.argsort(importance)[::-1][:10]
    print("Top 10 features:")
    for rank, idx in enumerate(top):
        print(f"  {rank+1:2d}. {FEATURE_NAMES[idx]:<25s} {importance[idx]:.4f}")

    return model


# ── Step 3: Export to C matching tc_model.h ──────────────────────────

def emit_tree_node(node, lines, depth):
    indent = "\t" * depth
    if "leaf" in node:
        lines.append(f"{indent}return {node['leaf']:.8f}f;")
        return

    feat_raw = node["split"]
    feat_idx = int(feat_raw[1:]) if isinstance(feat_raw, str) and feat_raw.startswith("f") else int(feat_raw)
    threshold = node["split_condition"]
    children = {child["nodeid"]: child for child in node.get("children", [])}
    yes_child = node.get("yes", 0)
    no_child = node.get("no", 0)

    lines.append(f"{indent}if (f[{feat_idx}] < {threshold:.8f}f) {{")
    if yes_child in children:
        emit_tree_node(children[yes_child], lines, depth + 1)
    else:
        lines.append(f"{indent}\treturn 0.0f;")
    lines.append(f"{indent}}} else {{")
    if no_child in children:
        emit_tree_node(children[no_child], lines, depth + 1)
    else:
        lines.append(f"{indent}\treturn 0.0f;")
    lines.append(f"{indent}}}")


def export_to_c(model, output_path):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    booster = model.get_booster()
    dump = booster.get_dump(dump_format="json")
    num_trees = len(dump)

    config = json.loads(booster.save_config())
    num_classes = int(config.get("learner", {}).get(
        "learner_model_param", {}).get("num_class", N_CLASSES))

    trees_per_class = num_trees // num_classes

    lines = []
    lines.append('#include "tc_model.h"')
    lines.append("#include <math.h>")
    lines.append("#include <string.h>")
    lines.append("")
    lines.append(f"/* Auto-generated: {num_trees} trees, "
                 f"{num_classes} classes, {trees_per_class} trees/class */")
    lines.append("")

    for tree_idx, tree_json_str in enumerate(dump):
        tree = json.loads(tree_json_str)
        lines.append(f"static float tree_{tree_idx}(const float *f)")
        lines.append("{")
        emit_tree_node(tree, lines, 1)
        lines.append("}")
        lines.append("")

    lines.append("int tc_model_predict(const float *features, float *output)")
    lines.append("{")
    lines.append(f"\tfloat scores[{num_classes}];")
    lines.append(f"\tmemset(scores, 0, sizeof(scores));")
    lines.append("")

    for tree_idx in range(num_trees):
        class_idx = tree_idx % num_classes
        lines.append(f"\tscores[{class_idx}] += tree_{tree_idx}(features);")

    lines.append("")
    lines.append("\t/* softmax */")
    lines.append("\tfloat max_s = scores[0];")
    lines.append(f"\tfor (int i = 1; i < {num_classes}; i++)")
    lines.append("\t\tif (scores[i] > max_s) max_s = scores[i];")
    lines.append("")
    lines.append("\tfloat sum_exp = 0.0f;")
    lines.append(f"\tfor (int i = 0; i < {num_classes}; i++) {{")
    lines.append("\t\tscores[i] = expf(scores[i] - max_s);")
    lines.append("\t\tsum_exp += scores[i];")
    lines.append("\t}")
    lines.append("")
    lines.append("\tint best = 0;")
    lines.append("\tfloat best_prob = 0.0f;")
    lines.append(f"\tfor (int i = 0; i < {num_classes}; i++) {{")
    lines.append("\t\toutput[i] = scores[i] / sum_exp;")
    lines.append("\t\tif (output[i] > best_prob) {")
    lines.append("\t\t\tbest_prob = output[i];")
    lines.append("\t\t\tbest = i;")
    lines.append("\t\t}")
    lines.append("\t}")
    lines.append("")
    lines.append("\treturn best;")
    lines.append("}")
    lines.append("")
    lines.append("int tc_model_available(void)")
    lines.append("{")
    lines.append("\treturn 1;")
    lines.append("}")
    lines.append("")

    with open(output_path, "w", newline="\n") as f:
        f.write("\n".join(lines))

    size_kb = os.path.getsize(output_path) / 1024
    print(f"\nGenerated {output_path}")
    print(f"  Size: {size_kb:.1f} KB")
    print(f"  Trees: {num_trees} ({trees_per_class} per class)")
    print(f"  Implements: tc_model_predict(), tc_model_available()")


# ── Load real data from CSV ───────────────────────────────────────────

def load_real_data(csv_path):
    """Load training data exported by the data_collect module."""
    print(f"  Loading real data from {csv_path}...")
    X_list, y_list = [], []
    skipped = 0

    with open(csv_path, "r") as f:
        reader = csv.reader(f)
        header = next(reader)

        for row in reader:
            if len(row) < N_FEATURES + 1:
                skipped += 1
                continue
            try:
                features = [float(row[i]) for i in range(N_FEATURES)]
                label = int(row[N_FEATURES])
                if 0 <= label < N_CLASSES:
                    X_list.append(features)
                    y_list.append(label)
                else:
                    skipped += 1
            except (ValueError, IndexError):
                skipped += 1

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)
    print(f"  Loaded {len(X)} rows ({skipped} skipped)")
    return X, y


# ── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Train XGBoost traffic classifier and export to C")
    parser.add_argument("--input", "-i", type=str, default=None,
                        help="Path to real training data CSV "
                             "(exported by the router's data_collect module)")
    parser.add_argument("--augment", "-a", action="store_true",
                        help="When using --input, also add synthetic data "
                             "to fill gaps in under-represented classes")
    parser.add_argument("--samples", "-n", type=int, default=10000,
                        help="Number of synthetic samples (default: 10000)")
    args = parser.parse_args()

    print("=" * 60)
    print("  Traffic Classifier — ML Model Builder")
    print("=" * 60)

    if args.input:
        print(f"\n[1/3] Loading real training data...")
        X, y = load_real_data(args.input)

        if args.augment:
            print(f"\n  Augmenting with {args.samples} synthetic flows...")
            X_synth, y_synth = generate_data(args.samples)
            X = np.vstack([X, X_synth])
            y = np.concatenate([y, y_synth])
            print(f"  Combined dataset: {len(X)} flows")
    else:
        n_samples = args.samples
        print(f"\n[1/3] Generating {n_samples} synthetic training flows...")
        X, y = generate_data(n_samples)

    unique, counts = np.unique(y, return_counts=True)
    for cls_id, count in zip(unique, counts):
        name = CLASS_NAMES[cls_id] if cls_id < len(CLASS_NAMES) else f"c{cls_id}"
        print(f"  {name:>10s}: {count:5d}")
    print(f"  Total: {len(X)} flows, {N_FEATURES} features")

    print(f"\n[2/3] Training XGBoost (100 trees, depth=6)...")
    model = train_model(X, y)

    model_dir = os.path.join(os.path.dirname(__file__), "model")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "classifier.xgb")
    model.save_model(model_path)
    print(f"\nSaved model: {model_path}")

    c_output = os.path.abspath(os.path.join(SRC_DIR, "tc_model_xgb.c"))
    print(f"\n[3/3] Exporting model to C → {c_output}")
    export_to_c(model, c_output)

    print(f"\n{'='*60}")
    print("  Done! The model has been exported to tc_model_xgb.c")
    if args.input:
        print(f"  Trained on: {len(X)} real+synthetic flows")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
