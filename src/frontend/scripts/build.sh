#!/bin/bash

set -e  # Exit on error

echo "======================================"
echo "System Hardening Tool - Build Script"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

# Get the directory of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Step 1: Install dependencies if needed
if [ ! -d "node_modules" ]; then
    print_info "Installing dependencies..."
    npm install
    print_success "Dependencies installed"
else
    print_info "Dependencies already installed"
fi

# Step 2: Build React frontend
print_info "Building React frontend..."
npm run build

if [ $? -eq 0 ]; then
    print_success "React frontend built successfully"
else
    print_error "React frontend build failed"
    exit 1
fi

# Step 3: Package Electron app for all platforms
print_info "Packaging Electron app for all platforms..."
echo ""

# Check if electron and electron-builder are installed
if ! command -v electron &> /dev/null; then
    print_info "Installing Electron and electron-builder..."
    npm install
fi

# Determine which platforms to build for based on command line argument
PLATFORM="${1:-all}"

case "$PLATFORM" in
    "windows"|"win")
        print_info "Building for Windows..."
        npm run package -- --win
        ;;
    "linux")
        print_info "Building for Linux..."
        npm run package -- --linux
        ;;
    "mac"|"darwin")
        print_info "Building for macOS..."
        npm run package -- --mac
        ;;
    "all")
        print_info "Building for all platforms (Windows, Linux, macOS)..."
        npm run package-all
        ;;
    *)
        print_error "Unknown platform: $PLATFORM"
        echo "Usage: $0 [windows|linux|mac|all]"
        exit 1
        ;;
esac

if [ $? -eq 0 ]; then
    print_success "Electron app packaged successfully"
    echo ""
    print_info "Installers created in: ${PROJECT_DIR}/dist"
    echo ""

    # List created installers
    if [ -d "${PROJECT_DIR}/dist" ]; then
        print_info "Created installers:"
        ls -lh "${PROJECT_DIR}/dist" | grep -E '\.(exe|dmg|AppImage|deb|rpm|zip)$' || echo "No installers found"
    fi
else
    print_error "Electron app packaging failed"
    exit 1
fi

echo ""
print_success "Build process completed successfully!"
echo ""
echo "To test the app locally, run: npm run electron"
echo ""
