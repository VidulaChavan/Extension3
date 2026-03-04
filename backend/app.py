"""
PhishGuard Flask API
Clean ML + Trusted Domain Architecture
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import logging
from typing import Dict, Any

# Import our modules
from utils.model_loader import ModelLoader
from utils.config import get_config
from feature_extraction.url_features import URLFeatureExtractor
from feature_extraction.email_features import EmailFeatureExtractor
from schemas.request_schemas import (
    URLPredictRequest, EmailPredictRequest,
    HealthResponse, ErrorResponse
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Load config
config = get_config()

# Initialize loaders instead of raw models
url_loader = ModelLoader('url')
email_loader = ModelLoader('email')

url_extractor = URLFeatureExtractor()
email_extractor = EmailFeatureExtractor()


def load_models():
    """Load ML models at startup"""
    try:
        logger.info("Loading URL model...")
        url_loader.load_model()
        logger.info("✅ URL model loaded successfully")
    except Exception as e:
        logger.error(f"❌ Failed to load URL model: {e}")

    try:
        logger.info("Loading Email model...")
        email_loader.load_model()
        logger.info("✅ Email model loaded successfully")
    except Exception as e:
        logger.error(f"❌ Failed to load Email model: {e}")


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    response = HealthResponse(
        status='healthy',
        version='2.0.0',
        models_loaded={
            'url': url_loader.is_model_loaded(),
            'email': email_loader.is_model_loaded()
        },
        timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
    )
    return jsonify(response.dict()), 200


@app.route('/predict/url', methods=['POST'])
def predict_url():
    """
    Predict if a URL is phishing
    Expected JSON: {
        "url": "https://example.com",
        "page_text": "optional page text",
        "links_count": 0
    }
    """
    start_time = time.time()

    try:
        # Parse request
        data = request.get_json()
        req = URLPredictRequest(**data)

        if not url_loader.is_model_loaded():
            return jsonify(ErrorResponse(
                error="Model not loaded",
                detail="URL model not available.",
                status_code=503
            ).dict()), 503

        # Extract normalized features
        features = url_extractor.extract_features_array(
            req.url,
            req.page_text,
            req.links_count
        )

        # 🔥 Use ModelLoader for prediction (scaler + trusted logic)
        result = url_loader.predict(features, url=req.url)

        response = {
            'url': req.url,
            **result,
            'processing_time_ms': (time.time() - start_time) * 1000
        }

        if req.return_features:
            response['features'] = features_dict
            response['feature_names'] = url_extractor.get_feature_names()

        logger.info(
            f"URL prediction: {req.url[:50]} -> "
            f"{response['risk_level']} ({response['risk_score']:.2f})"
        )

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error in URL prediction: {e}")
        return jsonify(ErrorResponse(
            error="Prediction failed",
            detail=str(e),
            status_code=400
        ).dict()), 400


@app.route('/predict/email', methods=['POST'])
def predict_email():
    """
    Predict if an email is phishing
    Expected JSON: {
        "subject": "Email subject",
        "body": "Email body",
        "links": ["link1", "link2"]
    }
    """
    start_time = time.time()

    try:
        # Parse request
        data = request.get_json()
        req = EmailPredictRequest(**data)

        if not email_loader.is_model_loaded():
            return jsonify(ErrorResponse(
                error="Model not loaded",
                detail="Email model not available.",
                status_code=503
            ).dict()), 503

        features = email_extractor.extract_features_array(
            req.subject, req.body, req.links
        )

        result = email_loader.predict(features)

        response = {
            'subject': req.subject[:50] + '...' if len(req.subject) > 50 else req.subject,
            **result,
            'processing_time_ms': (time.time() - start_time) * 1000
        }

        if req.return_features:
            response['features'] = features_dict
            response['feature_names'] = email_extractor.get_feature_names()

        logger.info(
            f"Email prediction -> "
            f"{response['risk_level']} ({response['risk_score']:.2f})"
        )

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Error in Email prediction: {e}")
        return jsonify(ErrorResponse(
            error="Prediction failed",
            detail=str(e),
            status_code=400
        ).dict()), 400

@app.route('/features/url', methods=['POST'])
def extract_url_features_only():
    """Just extract URL features without prediction"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        page_text = data.get('page_text', '')
        links_count = data.get('links_count', 0)
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        features = url_extractor.extract_features(url, page_text, links_count)
        return jsonify({
            'url': url,
            'features': features,
            'feature_names': url_extractor.get_feature_names()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/features/email', methods=['POST'])
def extract_email_features_only():
    """Just extract email features without prediction"""
    try:
        data = request.get_json()
        subject = data.get('subject', '')
        body = data.get('body', '')
        links = data.get('links', [])
        
        features = email_extractor.extract_features(subject, body, links)
        return jsonify({
            'features': features,
            'feature_names': email_extractor.get_feature_names()
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/info', methods=['GET'])
def get_info():
    """Get model and feature information"""
    return jsonify({
        'version': '2.0.0',
        'url_features': url_extractor.get_feature_names(),
        'email_features': email_extractor.get_feature_names(),
        'risk_thresholds': {
            'safe': 30,
            'suspicious': 60,
            'dangerous': 100
        },
        'models_loaded': {
            'url': url_loader.is_model_loaded(),
            'email': email_loader.is_model_loaded()
        }
    }), 200


# Load models at startup
load_models()

if __name__ == '__main__':
    app.run(
        host=config.API_HOST,
        port=config.API_PORT,
        debug=config.DEBUG
    )