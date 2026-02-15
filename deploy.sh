#!/bin/bash

echo "======================================"
echo "VEGGO Deployment Script"
echo "======================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Step 1: Checking Git repository...${NC}"
if [ -d .git ]; then
    echo -e "${GREEN}✓ Git repository found${NC}"
else
    echo "Initializing Git repository..."
    git init
    echo -e "${GREEN}✓ Git initialized${NC}"
fi

echo ""
echo -e "${YELLOW}Step 2: Creating .env file (if not exists)...${NC}"
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${GREEN}✓ .env file created from .env.example${NC}"
    echo -e "${YELLOW}⚠ Please edit .env file with your configuration!${NC}"
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

echo ""
echo -e "${YELLOW}Step 3: Creating gzipped archive...${NC}"
tar -czf veggo-service.tar.gz \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='venv' \
    --exclude='.env' \
    --exclude='*.tar.gz' \
    .
echo -e "${GREEN}✓ Created veggo-service.tar.gz${NC}"

echo ""
echo -e "${YELLOW}Step 4: Adding files to Git...${NC}"
git add .
echo -e "${GREEN}✓ Files added${NC}"

echo ""
echo -e "${YELLOW}Step 5: Ready to commit!${NC}"
echo ""
echo "Run the following commands to deploy:"
echo ""
echo "  git commit -m 'Deploy VEGGO service'"
echo "  git remote add origin <your-github-repo-url>"
echo "  git push -u origin main"
echo ""
echo "Then deploy to Koyeb:"
echo "  1. Go to https://app.koyeb.com"
echo "  2. Create new service"
echo "  3. Select GitHub repository"
echo "  4. Add environment variables from .env"
echo "  5. Deploy!"
echo ""
echo -e "${GREEN}======================================"
echo "Compressed archive: veggo-service.tar.gz"
echo "Size: $(du -h veggo-service.tar.gz | cut -f1)"
echo "======================================${NC}"
