"""Main application entry point"""
from app import app
from admin_routes import admin_bp
from agent_routes import agent_bp

# Register blueprints
app.register_blueprint(admin_bp)
app.register_blueprint(agent_bp)

if __name__ == '__main__':
    import os
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('DEBUG', 'False') == 'True')
