"""
NSL-KDD Dataset Training and Preprocessing Pipeline
--------------------------------------------------
This script demonstrates how to preprocess the NSL-KDD dataset,
handle class imbalances with SMOTE, train a Random Forest Classifier,
and export the model artifact to `nids_model.pkl` for deployment.
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# NSL-KDD Column Names
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

# Simplified 5-feature subset for fast inference / web demo:
SELECTED_FEATURES = ['duration', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent']

def train_and_save_model(data_path=None, model_output_path='nids_model.pkl'):
    """
    Trains a Random Forest model on the NSL-KDD dataset or mock data
    and dumps the serialized model to model_output_path.
    """
    if data_path and os.path.exists(data_path):
        print(f"Loading NSL-KDD dataset from: {data_path}")
        df = pd.read_csv(data_path, names=COLUMN_NAMES)
        
        # Map label to binary classification: 0 = Normal, 1 = Attack
        y = (df['label'] != 'normal').astype(int)
        X = df[SELECTED_FEATURES]
    else:
        print("No dataset path provided or file not found. Generating synthetic NSL-KDD sample for training demo...")
        np.random.seed(42)
        X = pd.DataFrame({
            'duration': np.random.exponential(scale=2.0, size=1000),
            'src_bytes': np.random.randint(0, 50000, size=1000),
            'dst_bytes': np.random.randint(0, 50000, size=1000),
            'wrong_fragment': np.random.choice([0, 1, 3], size=1000, p=[0.95, 0.03, 0.02]),
            'urgent': np.random.choice([0, 1], size=1000, p=[0.98, 0.02])
        })
        # Synthetic attack rule
        y = ((X['src_bytes'] > 20000) | (X['wrong_fragment'] > 0) | (X['urgent'] > 0)).astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Optional: SMOTE for class imbalance
    try:
        from imblearn.over_sampling import SMOTE
        smote = SMOTE(random_state=42)
        X_train, y_train = smote.fit_resample(X_train, y_train)
        print("Applied SMOTE for class rebalancing.")
    except ImportError:
        print("imbalanced-learn not installed, skipping SMOTE step.")

    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("\nModel Evaluation:")
    print(classification_report(y_test, y_pred))

    with open(model_output_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"Model successfully saved to '{model_output_path}'")

if __name__ == '__main__':
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(base_dir, 'nids_model.pkl')
    train_and_save_model(model_output_path=output_file)
