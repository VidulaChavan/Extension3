"""
URL Phishing Detection Model Training
Enhanced for 17 Feature Hybrid Detection
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import json
from datetime import datetime

from feature_extraction.url_features import URLFeatureExtractor


class URLModelTrainer:
    def __init__(self):
        self.extractor = URLFeatureExtractor()
        self.model = None
        self.scaler = StandardScaler()  # 🔥 Important for entropy + length features
        self.feature_names = self.extractor.get_feature_names()

    def load_and_prepare_data(self, dataset_path):
        """
        Load dataset and prepare features
        Expected CSV columns: 'url', 'label'
        Optional: 'page_text', 'links_count'
        """
        print("=" * 60)
        print("🔰 URL PHISHING MODEL TRAINING (17 FEATURES)")
        print("=" * 60)

        df = pd.read_csv(dataset_path)

        df['url'] = df['url'].fillna('').astype(str)

        if 'page_text' in df.columns:
            df['page_text'] = df['page_text'].fillna('').astype(str)
        else:
            df['page_text'] = ''

        if 'links_count' in df.columns:
            df['links_count'] = pd.to_numeric(df['links_count'], errors='coerce').fillna(0).astype(int)
        else:
            df['links_count'] = 0

        print(f"📊 Loaded {len(df)} samples")

        phishing_count = len(df[df['label'] == 1])
        legit_count = len(df[df['label'] == 0])
        print(f"   Phishing: {phishing_count}")
        print(f"   Legitimate: {legit_count}")

        print("🛠️ Extracting features...")
        X_list = []

        for idx, row in df.iterrows():
            if idx % 1000 == 0 and idx > 0:
                print(f"   Processed {idx} URLs...")

            url = str(row['url'])
            page_text = str(row['page_text'])
            links_count = int(row['links_count'])

            features = self.extractor.extract_features_array(url, page_text, links_count)
            X_list.append(features)

        X = np.array(X_list)
        y = df['label'].values

        print(f"✅ Feature matrix shape: {X.shape}")
        print(f"✅ Total features used: {X.shape[1]}")
        print(f"📌 Feature names: {self.feature_names}")

        # 🔥 Scale numerical features (important for entropy, length, digit counts)
        X = self.scaler.fit_transform(X)

        return X, y

    def train_model(self, X, y):
        print("\n🚀 Training Logistic Regression...")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )

        self.model = LogisticRegression(
            max_iter=2000,
            random_state=42,
            class_weight='balanced',
            solver='lbfgs'
        )

        self.model.fit(X_train, y_train)

        y_pred = self.model.predict(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        print("\n📊 Test Set Performance:")
        print(f"   Accuracy:  {accuracy:.4f}")
        print(f"   Precision: {precision:.4f}")
        print(f"   Recall:    {recall:.4f}")
        print(f"   F1-Score:  {f1:.4f}")

        cm = confusion_matrix(y_test, y_pred)
        print("\n📉 Confusion Matrix:")
        print(f"   TN: {cm[0,0]:4d}  FP: {cm[0,1]:4d}")
        print(f"   FN: {cm[1,0]:4d}  TP: {cm[1,1]:4d}")

        coefficients = self.model.coef_[0]
        print("\n📊 Feature Coefficients:")
        for name, coef in zip(self.feature_names, coefficients):
            print(f"   {name:25s}: {coef:.4f}")

        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'test_size': len(y_test)
        }

        return metrics

    def save_model(self, metrics):
        print("\n💾 Saving model...")

        models_dir = os.path.join(os.path.dirname(__file__), 'models')
        os.makedirs(models_dir, exist_ok=True)

        model_path = os.path.join(models_dir, 'url_model.pkl')
        scaler_path = os.path.join(models_dir, 'url_scaler.pkl')

        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)

        print(f"✅ Model saved to: {model_path}")
        print(f"✅ Scaler saved to: {scaler_path}")

        metadata = {
            'training_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'model_type': 'LogisticRegression',
            'feature_names': self.feature_names,
            'num_features': len(self.feature_names),
            'metrics': metrics,
            'coefficients': self.model.coef_[0].tolist(),
            'intercept': float(self.model.intercept_[0])
        }

        metadata_path = os.path.join(models_dir, 'url_model_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=4)

        print(f"✅ Metadata saved to: {metadata_path}")

        return model_path


def main():
    trainer = URLModelTrainer()

    dataset_path = '../dataset/url_dataset.csv'

    if not os.path.exists(dataset_path):
        print(f"\n❌ Dataset not found at: {dataset_path}")
        print("\nPlease add your URL dataset CSV file with columns:")
        print("   - url: the URL string")
        print("   - label: 1 for phishing, 0 for legitimate")
        print("   - page_text: (optional) page content")
        print("   - links_count: (optional) number of links")
        return

    try:
        # Prepare data
        X, y = trainer.load_and_prepare_data(dataset_path)
        
        # Train model
        metrics = trainer.train_model(X, y)
        
        # Save model
        trainer.save_model(metrics)

        print("\n" + "=" * 60)
        print("✅ URL MODEL TRAINING COMPLETED SUCCESSFULLY!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Error during training: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()