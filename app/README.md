# Intelligent Network Intrusion Detection System (NIDS)

A machine learning-powered Network Intrusion Detection System trained on the Kaggle NSL-KDD dataset, exposed as a Flask web portal/API, and designed for deployment on **Render** behind **Cloudflare** WAF/Reverse Proxy.

---

## 📁 Project Structure

```
app/
├── app.py              # Flask web portal & prediction API
├── train.py            # NSL-KDD model training, SMOTE & pickle generator
├── requirements.txt    # Python dependencies for Render build
└── nids_model.pkl      # Pickled trained Random Forest model artifact
```

---

## 🚀 Local Setup & Testing

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **(Optional) Retrain or generate model artifact:**
   ```bash
   python train.py
   ```

3. **Run the Flask application:**
   ```bash
   python app.py
   ```
   Open `http://127.0.0.1:5000` in your web browser.

---

## 🌐 Cloud Deployment (Render + Cloudflare)

### Phase 1: Deploy to Render
1. Push this directory to your GitHub repository.
2. In the [Render Dashboard](https://dashboard.render.com), click **New +** > **Web Service**.
3. Select your repository and configure:
   - **Environment:** `Python 3`
   - **Root Directory:** `app` (if files are inside `app/` folder)
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
4. Click **Deploy Web Service** and note your `*.onrender.com` URL.

### Phase 2: Secure with Cloudflare
1. Add your custom domain to [Cloudflare](https://dash.cloudflare.com).
2. Configure a DNS CNAME record:
   - **Type:** `CNAME`
   - **Name:** `nids` (or `@` for apex)
   - **Target:** `<your-app-name>.onrender.com`
   - **Proxy status:** 🟧 **Proxied**
3. Set SSL/TLS encryption mode to **Full**.
4. In Render Service Settings > **Custom Domains**, add and verify your domain (e.g. `nids.yourdomain.com`).
