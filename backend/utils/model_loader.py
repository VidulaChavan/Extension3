"""
Model Loader Utility
Loads trained models and makes predictions
Now supports optional feature scaling (for URL model)
"""

import joblib
import os
import numpy as np
from .config import get_config

config = get_config()

class ModelLoader:
    def __init__(self, model_type='url'):
        """
        Initialize model loader
        model_type: 'url' or 'email'
        """
        self.model_type = model_type
        self.model = None
        self.scaler = None  # 🔥 NEW

        # Model paths
        if model_type == 'url':
            self.model_path = config.URL_MODEL_PATH
            self.scaler_path = self.model_path.replace('url_model.pkl', 'url_scaler.pkl')
        else:
            self.model_path = config.EMAIL_MODEL_PATH
            self.scaler_path = None  # Email model doesn't use scaler

    def load_model(self):
        """Load the trained model (and scaler if URL model)"""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model not found at {self.model_path}. Please train the model first."
            )

        self.model = joblib.load(self.model_path)
        print(f"✅ {self.model_type.upper()} model loaded from {self.model_path}")

        # 🔥 Load scaler only for URL model
        if self.model_type == 'url' and self.scaler_path and os.path.exists(self.scaler_path):
            self.scaler = joblib.load(self.scaler_path)
            print(f"✅ URL scaler loaded from {self.scaler_path}")

        return self.model

    def predict(self, features):
        """
        Make prediction
        features: numpy array or list of features
        Returns: probability and class
        """
        if self.model is None:
            self.load_model()

        # Convert to numpy array if needed
        if isinstance(features, list):
            features = np.array(features)
        
        if len(features.shape) == 1:
            features = features.reshape(1, -1)

        # 🔥 Apply scaling for URL model
        if self.model_type == 'url' and self.scaler is not None:
            features = self.scaler.transform(features)

        # Get probability
        probability = self.model.predict_proba(features)[0][1]

        # Get class
        prediction = self.model.predict(features)[0]

        # Calculate risk score (0-100)
        risk_score = probability * 100

        # Determine risk level
        if risk_score <= config.RISK_THRESHOLDS['safe']:
            risk_level = 'Safe'
        elif risk_score <= config.RISK_THRESHOLDS['suspicious']:
            risk_level = 'Suspicious'
        else:
            risk_level = 'Dangerous'

        return {
            'probability': float(probability),
            'risk_score': float(risk_score),
            'risk_level': risk_level,
            'prediction': int(prediction),
            'is_phishing': bool(prediction == 1)
        }

    def is_model_loaded(self):
        """Check if model is loaded"""
        return self.model is not None