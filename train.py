"""
PhishShield AI - Machine Learning Training Pipeline
Domain-separated cross-validation training on URL structural features.
"""

import argparse
import os
import sys
import time
import joblib
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit

# Ensure local imports
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from core.feature_extractor import FEATURE_COLUMNS


def find_dataset(custom_path: str = None) -> str:
    """Auto-detect dataset path."""
    candidates = [
        custom_path,
        "Dataset.csv",
        os.path.join(CURRENT_DIR, "Dataset.csv"),
        os.path.join(os.path.expanduser("~"), "Downloads", "Dataset.csv"),
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return os.path.abspath(p)
    raise FileNotFoundError("Could not locate 'Dataset.csv'. Please supply --data <path_to_csv>.")


def run_training(
    data_path: str,
    output_model_path: str = "phishshield_model_v1.pkl",
    test_size: float = 0.20,
    random_state: int = 42,
):
    print("=" * 65)
    print("  🛡️  PhishShield AI - Model Training Pipeline")
    print("=" * 65)

    start_time = time.time()
    csv_path = find_dataset(data_path)
    print(f"\n[+] Loading dataset from: {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"    Raw records loaded: {len(df):,} rows, {df.shape[1]} columns")

    # Deduplication
    orig_len = len(df)
    df = df.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    print(f"    Deduplication removed: {orig_len - len(df):,} duplicate URLs")
    print(f"    Clean records: {len(df):,}")

    # Class distribution
    counts = df["label"].value_counts().to_dict()
    pcts = (df["label"].value_counts(normalize=True) * 100).to_dict()
    print(f"    Class distribution: Benign (0): {counts.get(0, 0):,} ({pcts.get(0, 0.0):.1f}%) | "
          f"Phishing (1): {counts.get(1, 0):,} ({pcts.get(1, 0.0):.1f}%)")

    # Features and Target
    target = "label"
    feature_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    print(f"\n[+] Input features verified ({len(feature_cols)}/{len(FEATURE_COLUMNS)})")

    # GroupShuffleSplit by Domain (eliminating domain data leakage)
    print("\n[+] Setting up Domain-Separated GroupShuffleSplit...")
    groups = df["dom"].fillna("unknown").astype(str)
    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=random_state)
    train_idx, test_idx = next(splitter.split(df[feature_cols], df[target], groups=groups))

    X_train = df.iloc[train_idx][feature_cols]
    y_train = df.iloc[train_idx][target]
    X_test = df.iloc[test_idx][feature_cols]
    y_test = df.iloc[test_idx][target]

    print(f"    Training samples: {len(X_train):,} across {groups.iloc[train_idx].nunique():,} distinct domains")
    print(f"    Testing samples:  {len(X_test):,} across {groups.iloc[test_idx].nunique():,} distinct domains")
    shared_domains = len(set(groups.iloc[train_idx]) & set(groups.iloc[test_idx]))
    print(f"    Shared domains between train & test: {shared_domains} (Zero leakage verified)")

    # Model Initialization
    print("\n[+] Training HistGradientBoostingClassifier (max_iter=150, lr=0.1)...")
    model = HistGradientBoostingClassifier(
        max_iter=150,
        learning_rate=0.1,
        random_state=random_state,
    )

    t0 = time.time()
    model.fit(X_train, y_train)
    fit_duration = time.time() - t0
    print(f"    Training completed in {fit_duration:.2f} seconds.")

    # Evaluation
    print("\n[+] Evaluating performance on unseen domains test set...")
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label=1)
    rec = recall_score(y_test, y_pred, pos_label=1)
    f1 = f1_score(y_test, y_pred, pos_label=1)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 45)
    print("  🏆 Benchmark Evaluation Results")
    print("=" * 45)
    print(f"  • Overall Test Accuracy:   {acc * 100:.2f}%")
    print(f"  • Phishing Precision:      {prec * 100:.2f}%")
    print(f"  • Phishing Recall:         {rec * 100:.2f}%")
    print(f"  • Phishing F1 Score:       {f1:.4f}")
    print("\n  Confusion Matrix:")
    print(f"    [[TN={cm[0][0]:<5}  FP={cm[0][1]:<5}]")
    print(f"     [FN={cm[1][0]:<5}  TP={cm[1][1]:<5}]]")
    print("\n" + classification_report(y_test, y_pred, digits=4))

    # Save model package
    package = {
        "model": model,
        "feature_columns": feature_cols,
        "version": "v1.0-domain-split",
        "accuracy": acc,
        "f1_score": f1,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    out_path = os.path.abspath(output_model_path)
    joblib.dump(package, out_path)
    print(f"[✓] Successfully exported trained model to: {out_path}")
    print(f"    File size: {os.path.getsize(out_path) / 1024:.1f} KB")
    print(f"    Total elapsed time: {time.time() - start_time:.2f} seconds.")


def main():
    parser = argparse.ArgumentParser(description="Train PhishShield AI Model")
    parser.add_argument("--data", "-d", default=None, help="Path to Dataset.csv")
    parser.add_argument("--out", "-o", default="phishshield_model_v1.pkl", help="Output model path")
    parser.add_argument("--test-size", type=float, default=0.20, help="Test set fraction")
    args = parser.parse_args()

    run_training(data_path=args.data, output_model_path=args.out, test_size=args.test_size)


if __name__ == "__main__":
    main()
