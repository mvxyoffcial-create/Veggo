# VEGGO Quick Start Guide

## 🚀 Fast Deployment to Koyeb

### Prerequisites Checklist
- [ ] GitHub account
- [ ] MongoDB Atlas account (free tier available)
- [ ] Gmail account with App Password
- [ ] Koyeb account (free tier available)

### Step 1: Setup MongoDB (5 minutes)

1. Go to https://www.mongodb.com/cloud/atlas/register
2. Create a free cluster
3. Create database user:
   - Username: veggo_user
   - Password: (generate strong password)
4. Network Access: Add `0.0.0.0/0` (allow from anywhere)
5. Get connection string:
   - Click "Connect" → "Connect your application"
   - Copy the connection string
   - Replace `<password>` with your password
   - Example: `mongodb+srv://veggo_user:PASSWORD@cluster0.xxxxx.mongodb.net/veggo_db`

### Step 2: Setup Gmail App Password (3 minutes)

1. Enable 2-Factor Authentication on Gmail
2. Go to https://myaccount.google.com/apppasswords
3. Select "App": Other (Custom name) → "VEGGO"
4. Click "Generate"
5. Copy the 16-character password (no spaces)

### Step 3: Deploy to Koyeb (5 minutes)

1. **Push to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial VEGGO deployment"
   git remote add origin https://github.com/YOUR_USERNAME/veggo-service.git
   git push -u origin main
   ```

2. **Deploy on Koyeb:**
   - Go to https://app.koyeb.com
   - Click "Create Service"
   - Select "GitHub" as source
   - Choose your `veggo-service` repository
   - Select branch: `main`
   
3. **Configure Build:**
   - Build command: `pip install -r requirements.txt`
   - Run command: `gunicorn main:app --bind 0.0.0.0:$PORT --workers 4`
   
4. **Add Environment Variables:**
   Click "Advanced" → "Environment Variables" → Add these:
   
   ```
   SECRET_KEY = (generate random 32-char string)
   JWT_SECRET = (generate random 32-char string)
   MONGO_URI = mongodb+srv://veggo_user:PASSWORD@cluster0.xxxxx.mongodb.net/veggo_db
   MAIL_SERVER = smtp.gmail.com
   MAIL_PORT = 587
   MAIL_USERNAME = your-email@gmail.com
   MAIL_PASSWORD = (your 16-char app password)
   MAIL_DEFAULT_SENDER = noreply@veggo.com
   BASE_URL = https://your-app-name.koyeb.app
   DEBUG = False
   ```
   
   **Generate random keys:**
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

5. **Deploy!**
   - Click "Create Service"
   - Wait 2-3 minutes for deployment
   - Your app will be live at: `https://your-app-name.koyeb.app`

### Step 4: Create Admin Account (2 minutes)

Use MongoDB Atlas web interface:

1. Go to your cluster → "Collections"
2. Find database `veggo_db`
3. Create collection `admins`
4. Insert document:
   ```json
   {
     "username": "admin",
     "email": "admin@veggo.com",
     "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5NU7sQXxgCf0m",
     "created_at": {"$date": "2024-01-01T00:00:00.000Z"}
   }
   ```
   **Note:** This hash is for password: `admin123` (change it after first login!)

OR use Python script:
```python
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from datetime import datetime

client = MongoClient('YOUR_MONGO_URI')
db = client['veggo_db']

db.admins.insert_one({
    'username': 'admin',
    'email': 'admin@veggo.com',
    'password': generate_password_hash('admin123'),
    'created_at': datetime.utcnow()
})
print("Admin created!")
```

### Step 5: Test Your Deployment

1. **API Health Check:**
   ```bash
   curl https://your-app-name.koyeb.app/health
   ```

2. **Admin Panel:**
   - Go to: `https://your-app-name.koyeb.app/admin/login`
   - Login with: admin@veggo.com / admin123

3. **Agent Panel:**
   - Go to: `https://your-app-name.koyeb.app/agent/signup`
   - Register a delivery agent

4. **Test API:**
   ```bash
   curl -X POST https://your-app-name.koyeb.app/api/v1/auth/signup \
     -H "Content-Type: application/json" \
     -d '{
       "username": "testuser",
       "email": "test@example.com",
       "phone": "1234567890",
       "password": "password123"
     }'
   ```

## 🎯 Post-Deployment Checklist

- [ ] Admin panel accessible
- [ ] Agent panel accessible
- [ ] API endpoints responding
- [ ] Email verification working
- [ ] Order creation working
- [ ] PDF bill generation working

## 📊 Monitoring

**Koyeb Dashboard:**
- Logs: Real-time application logs
- Metrics: CPU, Memory, Network usage
- Health: Service health status

**MongoDB Atlas:**
- Database size and usage
- Connection statistics
- Performance metrics

## 🔧 Troubleshooting

### Service won't start
- Check Koyeb logs for errors
- Verify all environment variables are set
- Check MongoDB connection string

### Emails not sending
- Verify Gmail App Password (no spaces)
- Check MAIL_USERNAME is correct
- Ensure 2FA is enabled on Gmail

### Database connection failed
- Verify MongoDB Atlas IP whitelist (0.0.0.0/0)
- Check database user credentials
- Ensure connection string has correct password

### 404 Errors
- Check BASE_URL environment variable
- Verify routes in app.py
- Check Koyeb deployment logs

## 🔐 Security Checklist

- [ ] Change default admin password
- [ ] Use strong SECRET_KEY and JWT_SECRET
- [ ] MongoDB has strong password
- [ ] Gmail App Password is secure
- [ ] BASE_URL matches your Koyeb URL
- [ ] DEBUG is set to False

## 📚 Next Steps

1. **Customize the app:**
   - Add your logo to templates
   - Customize email templates
   - Add more product categories

2. **Add features:**
   - Payment gateway integration
   - Real-time order tracking
   - Mobile app API

3. **Scale:**
   - Increase Koyeb instances
   - Optimize database queries
   - Add Redis caching

## 🆘 Support

- GitHub Issues: Report bugs
- Documentation: README.md
- API Docs: /api/v1 endpoint

---

**Total Setup Time: ~15 minutes** 🎉

Your VEGGO service is now live and ready to accept orders!
