#!/bin/bash

# start-dev.sh - Development startup script for Linux/Mac
# Starts Flask backend, React dev server, and Electron

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
FLASK_PORT=5000
REACT_PORT=3000
MAX_WAIT=60
CHECK_INTERVAL=2

# Process IDs
FLASK_PID=""
REACT_PID=""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up processes...${NC}"

    # Kill Flask backend
    if [ ! -z "$FLASK_PID" ]; then
        echo -e "${BLUE}Stopping Flask backend (PID: $FLASK_PID)...${NC}"
        kill $FLASK_PID 2>/dev/null || true
        wait $FLASK_PID 2>/dev/null || true
    fi

    # Kill React dev server
    if [ ! -z "$REACT_PID" ]; then
        echo -e "${BLUE}Stopping React dev server (PID: $REACT_PID)...${NC}"
        kill $REACT_PID 2>/dev/null || true
        wait $REACT_PID 2>/dev/null || true
    fi

    # Kill any remaining processes on the ports
    if command -v lsof &> /dev/null; then
        FLASK_PORT_PID=$(lsof -ti:$FLASK_PORT 2>/dev/null || true)
        if [ ! -z "$FLASK_PORT_PID" ]; then
            echo -e "${BLUE}Killing process on port $FLASK_PORT...${NC}"
            kill -9 $FLASK_PORT_PID 2>/dev/null || true
        fi

        REACT_PORT_PID=$(lsof -ti:$REACT_PORT 2>/dev/null || true)
        if [ ! -z "$REACT_PORT_PID" ]; then
            echo -e "${BLUE}Killing process on port $REACT_PORT...${NC}"
            kill -9 $REACT_PORT_PID 2>/dev/null || true
        fi
    fi

    echo -e "${GREEN}Cleanup complete${NC}"
    exit 0
}

# Register cleanup function for various exit signals
trap cleanup EXIT INT TERM

# Check if port is available
check_port_available() {
    local port=$1
    if command -v lsof &> /dev/null; then
        ! lsof -i:$port -sTCP:LISTEN -t >/dev/null 2>&1
    elif command -v netstat &> /dev/null; then
        ! netstat -tuln | grep -q ":$port "
    else
        # Fallback: try to connect
        ! nc -z localhost $port 2>/dev/null
    fi
}

# Wait for service to be ready
wait_for_service() {
    local port=$1
    local service_name=$2
    local elapsed=0

    echo -e "${BLUE}Waiting for $service_name on port $port...${NC}"

    while [ $elapsed -lt $MAX_WAIT ]; do
        if ! check_port_available $port; then
            echo -e "${GREEN}$service_name is ready!${NC}"
            return 0
        fi

        sleep $CHECK_INTERVAL
        elapsed=$((elapsed + CHECK_INTERVAL))
        echo -e "${YELLOW}Waiting... ($elapsed/${MAX_WAIT}s)${NC}"
    done

    echo -e "${RED}Timeout waiting for $service_name${NC}"
    return 1
}

# Main script
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  System Hardening Tool - Dev Startup  ${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Get project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo -e "${BLUE}Project root: $PROJECT_ROOT${NC}\n"

# Check if required directories exist
if [ ! -d "$PROJECT_ROOT/src/backend" ]; then
    echo -e "${RED}Error: Backend directory not found${NC}"
    exit 1
fi

if [ ! -d "$PROJECT_ROOT/src/frontend" ]; then
    echo -e "${RED}Error: Frontend directory not found${NC}"
    exit 1
fi

# Check if ports are available
echo -e "${BLUE}Checking port availability...${NC}"

if ! check_port_available $FLASK_PORT; then
    echo -e "${RED}Error: Port $FLASK_PORT is already in use${NC}"
    echo -e "${YELLOW}Please stop the process using this port or change FLASK_PORT${NC}"
    exit 1
fi

if ! check_port_available $REACT_PORT; then
    echo -e "${RED}Error: Port $REACT_PORT is already in use${NC}"
    echo -e "${YELLOW}Please stop the process using this port or change REACT_PORT${NC}"
    exit 1
fi

echo -e "${GREEN}Ports are available${NC}\n"

# Start Flask backend
echo -e "${BLUE}Starting Flask backend...${NC}"
cd "$PROJECT_ROOT"

# Determine Python command
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo -e "${RED}Error: Python not found${NC}"
    exit 1
fi

# Check if Flask app exists
FLASK_APP="$PROJECT_ROOT/src/backend/app.py"
if [ ! -f "$FLASK_APP" ]; then
    echo -e "${RED}Error: Flask app not found at $FLASK_APP${NC}"
    exit 1
fi

# Start Flask in background
FLASK_ENV=development PORT=$FLASK_PORT $PYTHON_CMD "$FLASK_APP" > "$PROJECT_ROOT/logs/flask.log" 2>&1 &
FLASK_PID=$!

echo -e "${GREEN}Flask backend started (PID: $FLASK_PID)${NC}"
echo -e "${YELLOW}Flask logs: $PROJECT_ROOT/logs/flask.log${NC}\n"

# Create logs directory if it doesn't exist
mkdir -p "$PROJECT_ROOT/logs"

# Wait for Flask to be ready
if ! wait_for_service $FLASK_PORT "Flask backend"; then
    echo -e "${RED}Failed to start Flask backend${NC}"
    echo -e "${YELLOW}Check logs at: $PROJECT_ROOT/logs/flask.log${NC}"
    exit 1
fi

# Start React dev server
echo -e "\n${BLUE}Starting React dev server...${NC}"
cd "$PROJECT_ROOT/src/frontend"

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo -e "${RED}Error: Frontend package.json not found${NC}"
    exit 1
fi

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}node_modules not found. Running npm install...${NC}"
    npm install
fi

# Start React dev server in background
npm run dev > "$PROJECT_ROOT/logs/react.log" 2>&1 &
REACT_PID=$!

echo -e "${GREEN}React dev server started (PID: $REACT_PID)${NC}"
echo -e "${YELLOW}React logs: $PROJECT_ROOT/logs/react.log${NC}\n"

# Wait for React to be ready
if ! wait_for_service $REACT_PORT "React dev server"; then
    echo -e "${RED}Failed to start React dev server${NC}"
    echo -e "${YELLOW}Check logs at: $PROJECT_ROOT/logs/react.log${NC}"
    exit 1
fi

# Start Electron
echo -e "\n${BLUE}Starting Electron...${NC}"
cd "$PROJECT_ROOT"

# Check if node_modules exists in root
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}node_modules not found in root. Running npm install...${NC}"
    npm install
fi

# Set environment variables for Electron
export NODE_ENV=development

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All services are ready!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${BLUE}Flask backend:     http://localhost:$FLASK_PORT${NC}"
echo -e "${BLUE}React dev server:  http://localhost:$REACT_PORT${NC}"
echo -e "${YELLOW}\nPress Ctrl+C to stop all services${NC}\n"

# Start Electron (this will block until Electron exits)
npm run electron:dev

# When Electron exits, cleanup will be called automatically
echo -e "${GREEN}Electron exited${NC}"
