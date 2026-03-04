#!/bin/bash
# S.O.N.I.C. - SIP Observation and Network Inspection Console - Setup Script
# Author: Raymond A Rizzo | Zombat

set -e

echo "🚀 Setting up S.O.N.I.C. (SIP Observation and Network Inspection Console)..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Python 3.8+ is installed
echo "🐍 Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is not installed. Please install Python 3.8 or higher.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.8"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo -e "${RED}❌ Python ${PYTHON_VERSION} detected. Sonic requires Python ${REQUIRED_VERSION} or higher.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Python ${PYTHON_VERSION} detected${NC}"

# Install system dependencies
echo "📦 Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    echo "📦 Detected Debian/Ubuntu - installing tshark..."
    sudo apt-get update
    sudo apt-get install -y tshark
elif command -v brew &> /dev/null; then
    echo "📦 Detected macOS - installing wireshark..."
    brew install wireshark
elif command -v yum &> /dev/null; then
    echo "📦 Detected RHEL/CentOS - installing wireshark..."
    sudo yum install -y wireshark-cli
else
    echo -e "${YELLOW}⚠️  Could not detect package manager. Please install tshark/Wireshark manually:${NC}"
    echo "   - Ubuntu/Debian: sudo apt-get install tshark"
    echo "   - macOS: brew install wireshark"
    echo "   - Windows: Download from https://www.wireshark.org/"
fi

# Check if tshark is available
if command -v tshark &> /dev/null; then
    echo -e "${GREEN}✅ tshark is available${NC}"
else
    echo -e "${YELLOW}⚠️  tshark not found in PATH. Sonic will use scapy fallback.${NC}"
fi

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
else
    pip3 install scapy dspy-ai pydantic tqdm ollama
fi

echo -e "${GREEN}✅ Python dependencies installed${NC}"

# Install Ollama (if not already installed)
echo "🤖 Setting up AI backend (Ollama)..."
if ! command -v ollama &> /dev/null; then
    echo "📥 Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo -e "${GREEN}✅ Ollama is already installed${NC}"
fi

# Check if Ollama is running and start if needed
if ! pgrep -x "ollama" > /dev/null; then
    echo "🚀 Starting Ollama service..."
    ollama serve &
    sleep 5
fi

# Pull required AI models
echo "📥 Downloading AI models..."
echo "   📊 Pulling fast model (qwen2.5:0.5b)..."
ollama pull qwen2.5:0.5b

echo "   🔍 Pulling detailed model (qwen2.5vl:7b)..."
ollama pull qwen2.5vl:7b

echo -e "${GREEN}✅ AI models downloaded${NC}"

# Test installation
echo "🧪 Testing S.O.N.I.C. installation..."
if python3 -c "import scapy, dspy, pydantic; print('✅ Core dependencies OK')" 2>/dev/null; then
    echo -e "${GREEN}✅ Core dependencies test passed${NC}"
else
    echo -e "${RED}❌ Core dependencies test failed${NC}"
    exit 1
fi

# Create a simple test
echo "🧪 Running basic functionality test..."
if python3 sonic.py --help > /dev/null 2>&1; then
    echo '✅ Sonic CLI test passed'
else
    echo '❌ Sonic CLI test failed'
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 S.O.N.I.C. (SIP Observation and Network Inspection Console) setup complete!${NC}"
echo ""
echo -e "${BLUE}📚 Quick Start:${NC}"
echo "   python3 sonic.py --file your_capture.pcapng --model combined"
echo ""
echo -e "${BLUE}⚡ Quality-Only Analysis (No LLM):${NC}"
echo "   python3 sonic.py --file your_capture.pcapng --quality-only"
echo ""
echo -e "${BLUE}📖 Documentation:${NC}"
echo "   See README.md for detailed usage instructions"
echo ""
echo -e "${BLUE}🔧 Test Installation:${NC}"
echo "   python3 sonic.py --help"
