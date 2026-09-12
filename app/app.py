# app.py
import os
import pickle
import requests
import numpy as np
from flask import Flask, request, jsonify

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'nids_model.pkl')

# Dummy model training and saving for initial fallback if model does not exist
def create_mock_model():
    from sklearn.ensemble import RandomForestClassifier
    X_mock = np.random.rand(100, 5)  # 5 simplified features
    y_mock = np.random.randint(0, 2, 100)
    model = RandomForestClassifier()
    model.fit(X_mock, y_mock)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)

if not os.path.exists(MODEL_PATH):
    create_mock_model()

# Load the trained model
with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

# Cloudflare D1 Configuration (via Environment Variables)
CF_ACCOUNT_ID = os.environ.get('CF_ACCOUNT_ID')
CF_DATABASE_ID = os.environ.get('CF_DATABASE_ID')
CF_API_TOKEN = os.environ.get('CF_API_TOKEN')

def log_to_cloudflare_d1(features, prediction, client_ip):
    """Persists packet audit record into Cloudflare D1."""
    if not (CF_ACCOUNT_ID and CF_DATABASE_ID and CF_API_TOKEN):
        return  # Silently skip if D1 environment variables are not configured
    
    url = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/d1/database/{CF_DATABASE_ID}/query"
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    sql = """
    INSERT INTO audit_logs (duration, src_bytes, dst_bytes, wrong_fragment, urgent, prediction, client_ip)
    VALUES (?, ?, ?, ?, ?, ?, ?);
    """
    payload = {
        "sql": sql,
        "params": [
            float(features[0]), int(features[1]), int(features[2]),
            int(features[3]), int(features[4]), prediction, client_ip
        ]
    }
    try:
        requests.post(url, json=payload, headers=headers, timeout=3)
    except Exception as err:
        print(f"Cloudflare D1 warning: {err}")

@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NIDS Cloud Portal</title>
        <style>
            * { box-sizing: border-box; }
            body { 
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
                background: #0f172a; 
                color: #f8fafc; 
                display: flex; 
                justify-content: center; 
                align-items: center; 
                min-height: 100vh; 
                margin: 0; 
                padding: 20px;
            }
            .card { 
                background: #1e293b; 
                padding: 2.5rem; 
                border-radius: 14px; 
                box-shadow: 0 12px 30px rgba(0,0,0,0.4); 
                width: 100%; 
                max-width: 500px; 
                border: 1px solid #334155; 
            }
            h2 { margin-top: 0; color: #38bdf8; font-size: 1.5rem; }
            p { color: #94a3b8; font-size: 0.95rem; margin-bottom: 1.5rem; }
            .form-group { margin-bottom: 14px; }
            label { display: block; margin-bottom: 5px; font-weight: 600; font-size: 0.88rem; color: #cbd5e1; }
            input[type="number"] { 
                width: 100%; 
                padding: 10px 12px; 
                border-radius: 6px; 
                border: 1px solid #475569; 
                background: #0f172a; 
                color: #f8fafc; 
                font-size: 0.95rem;
            }
            input[type="number"]:focus {
                outline: none;
                border-color: #38bdf8;
                box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
            }
            button { 
                width: 100%; 
                margin-top: 15px; 
                padding: 12px; 
                background: #0284c7; 
                border: none; 
                border-radius: 6px; 
                color: white; 
                font-weight: 700; 
                font-size: 1rem; 
                cursor: pointer; 
                transition: background 0.2s ease; 
            }
            button:hover { background: #0369a1; }
            #result { 
                margin-top: 20px; 
                padding: 14px; 
                border-radius: 6px; 
                display: none; 
                text-align: center; 
                font-weight: 700; 
                font-size: 1rem;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>🛡️ NIDS Cloud Security Portal</h2>
            <p>Analyze real-time network packet features to classify threats.</p>
            <form id="auditForm">
                <div class="form-group">
                    <label>Duration (ms):</label>
                    <input type="number" id="duration" step="any" value="0.1" required>
                </div>
                <div class="form-group">
                    <label>Source Bytes:</label>
                    <input type="number" id="src_bytes" value="150" required>
                </div>
                <div class="form-group">
                    <label>Destination Bytes:</label>
                    <input type="number" id="dst_bytes" value="340" required>
                </div>
                <div class="form-group">
                    <label>Wrong Fragments:</label>
                    <input type="number" id="wrong_fragment" value="0" required>
                </div>
                <div class="form-group">
                    <label>Urgent Packets:</label>
                    <input type="number" id="urgent" value="0" required>
                </div>
                <button type="button" onclick="runAudit()">Run Security Audit</button>
            </form>
            <div id="result"></div>
        </div>
        <script>
            async function runAudit() {
                const payload = {
                    features: [
                        parseFloat(document.getElementById('duration').value),
                        parseFloat(document.getElementById('src_bytes').value),
                        parseFloat(document.getElementById('dst_bytes').value),
                        parseFloat(document.getElementById('wrong_fragment').value),
                        parseFloat(document.getElementById('urgent').value)
                    ]
                };
                const resultDiv = document.getElementById('result');
                resultDiv.style.display = 'block';
                resultDiv.style.background = '#334155';
                resultDiv.style.color = '#f8fafc';
                resultDiv.innerText = "Analyzing packet...";

                try {
                    const res = await fetch('/predict', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json();
                    if(data.prediction && data.prediction.includes('Attack')) {
                        resultDiv.style.background = '#7f1d1d';
                        resultDiv.style.color = '#fecaca';
                        resultDiv.innerText = "🚨 ALERT: " + data.prediction;
                    } else {
                        resultDiv.style.background = '#14532d';
                        resultDiv.style.color = '#bbf7d0';
                        resultDiv.innerText = "✅ SAFE: " + data.prediction;
                    }
                } catch (err) {
                    resultDiv.style.background = '#7f1d1d';
                    resultDiv.style.color = '#fecaca';
                    resultDiv.innerText = "Error contacting inference engine.";
                }
            }
        </script>
    </body>
    </html>
    '''

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        features = data['features']
        input_array = np.array(features).reshape(1, -1)
        pred = model.predict(input_array)
        
        result = "Anomaly / Attack Detected" if pred[0] == 1 else "Normal Traffic"
        client_ip = request.headers.get('CF-Connecting-IP', request.remote_addr)
        
        log_to_cloudflare_d1(features, result, client_ip)
        return jsonify({'prediction': result, 'client_ip': client_ip})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)