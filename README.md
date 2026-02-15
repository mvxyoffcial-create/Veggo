# VEGGO - Vegetable Delivery System

A complete full-stack production-ready vegetable delivery platform with REST API, admin panel, and agent panel.

## Features

### Core Functionality
- ✅ REST API backend with JSON responses
- ✅ Server-rendered HTML admin panel
- ✅ Server-rendered HTML agent panel
- ✅ Email verification system
- ✅ Forgot password system
- ✅ Billing system with PDF generation
- ✅ Supplier management
- ✅ User order tracking
- ✅ Role-based authentication (USER, ADMIN, SUPPLIER, DELIVERY_AGENT)

### Authentication
- JWT-based authentication for API
- Session-based authentication for web panels
- Bcrypt password hashing
- Email verification on signup
- Password reset with 15-minute expiry tokens

### Order Management
- Complete order flow: pending → confirmed → packed → assigned_to_agent → out_for_delivery → delivered
- Real-time email notifications at each stage
- Downloadable PDF bills
- Order history tracking

### Admin Panel Features
- User management (view, block, delete)
- Product management (add, edit, delete)
- Agent management (approve, remove)
- Order management (view, assign to agents)
- Dashboard with statistics

### Agent Panel Features
- View assigned orders
- Accept delivery orders
- Mark orders as delivered
- Delivery history
- Customer contact information

## Technology Stack

- **Backend**: Python Flask
- **Database**: MongoDB
- **Authentication**: JWT + Session-based
- **Email**: Flask-Mail (SMTP)
- **PDF Generation**: ReportLab
- **Compression**: Gzip (Flask-Compress)
- **Server**: Gunicorn

## Installation

### Prerequisites
- Python 3.9+
- MongoDB (local or Atlas)
- SMTP server (Gmail recommended)

### Local Setup

1. Clone the repository:
```bash
git clone <your-repo-url>
cd veggo-service
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Run the application:
```bash
python main.py
```

The application will start at `http://localhost:5000`

## Deployment to Koyeb

### Step 1: Prepare MongoDB
1. Create a MongoDB Atlas account at https://www.mongodb.com/cloud/atlas
2. Create a cluster and get your connection string
3. Update `MONGO_URI` in your environment variables

### Step 2: Configure Email
1. For Gmail, enable 2-factor authentication
2. Generate an App Password: https://myaccount.google.com/apppasswords
3. Use the app password in `MAIL_PASSWORD`

### Step 3: Deploy to Koyeb

1. Push your code to GitHub:
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin <your-github-repo-url>
git push -u origin main
```

2. Sign up at https://www.koyeb.com

3. Create a new app:
   - Select "GitHub" as source
   - Choose your repository
   - Set build command: `pip install -r requirements.txt`
   - Set run command: `gunicorn main:app --bind 0.0.0.0:$PORT`

4. Add environment variables in Koyeb dashboard:
   - `SECRET_KEY`
   - `JWT_SECRET`
   - `MONGO_URI`
   - `MAIL_SERVER`
   - `MAIL_PORT`
   - `MAIL_USERNAME`
   - `MAIL_PASSWORD`
   - `MAIL_DEFAULT_SENDER`
   - `BASE_URL` (your Koyeb app URL)

5. Deploy!

## API Endpoints

### Authentication
- `POST /api/v1/auth/signup` - User registration
- `POST /api/v1/auth/login` - User login
- `GET /verify-email?token=<token>` - Verify email
- `POST /api/v1/auth/forgot-password` - Request password reset
- `POST /api/v1/auth/reset-password` - Reset password

### Products
- `GET /api/v1/products` - Get all products
- `GET /api/v1/products/<id>` - Get single product

### Orders
- `POST /api/v1/orders` - Create order (requires auth)
- `GET /api/v1/orders` - Get user orders (requires auth)
- `GET /api/v1/orders/<id>` - Get specific order (requires auth)
- `GET /api/v1/orders/<id>/bill` - Download bill PDF (requires auth)

### Addresses
- `POST /api/v1/addresses` - Add address (requires auth)
- `GET /api/v1/addresses` - Get addresses (requires auth)
- `PUT /api/v1/addresses/<id>` - Update address (requires auth)
- `DELETE /api/v1/addresses/<id>` - Delete address (requires auth)

## Web Panels

### Admin Panel
- URL: `/admin`
- Login: `/admin/login`
- Features: User, Product, Order, Agent management

### Agent Panel
- URL: `/agent`
- Login: `/agent/login`
- Signup: `/agent/signup`
- Features: Order delivery management

## Database Collections

- **users** - User accounts
- **admins** - Admin accounts
- **suppliers** - Supplier accounts
- **agents** - Delivery agent accounts
- **products** - Product catalog
- **orders** - Order records
- **addresses** - User addresses
- **bills** - Generated bills
- **email_tokens** - Verification and reset tokens

## Email Notifications

Automatic emails sent for:
- Account verification
- Password reset
- Order placed
- Order confirmed
- Agent assigned
- Out for delivery
- Order delivered

## Gzip Compression

All responses are automatically gzipped for:
- Faster data transfer
- Reduced bandwidth usage
- Better performance
- Easy Git repository management (smaller files)

Compression is configured in Flask-Compress with:
- Compression level: 6 (balanced)
- Minimum size: 500 bytes
- Supported types: HTML, CSS, JS, JSON, XML

## Security Features

- JWT token-based API authentication
- Password hashing with bcrypt
- Secure email tokens with expiry
- Role-based access control
- CORS protection
- Input validation
- SQL injection protection (MongoDB)

## Creating Admin Account

Use MongoDB shell or Compass:

```javascript
db.admins.insertOne({
  username: "admin",
  email: "admin@veggo.com",
  password: "$2b$12$<bcrypt-hash>",  // Use generate_password_hash('your-password')
  created_at: new Date()
})
```

Or use Python:
```python
from werkzeug.security import generate_password_hash
from pymongo import MongoClient

client = MongoClient('your-mongo-uri')
db = client['veggo_db']

db.admins.insert_one({
    'username': 'admin',
    'email': 'admin@veggo.com',
    'password': generate_password_hash('admin123'),
    'created_at': datetime.utcnow()
})
```

## License

MIT License

## Support

For issues and questions, please open an issue on GitHub.
