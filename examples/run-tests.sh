#!/bin/bash
set -e

echo "========================================"
echo "Examples - Integration Tests"
echo "========================================"
echo ""

# Change to the examples directory
cd "$(dirname "$0")"

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose is not installed"
    exit 1
fi

# Clean up any existing containers
echo "🧹 Cleaning up existing containers..."
docker-compose -f docker-compose.test.yml down -v 2>/dev/null || true

# Build and start services
echo "🏗️  Building Docker images..."
docker-compose -f docker-compose.test.yml build

echo "🚀 Starting services..."
docker-compose -f docker-compose.test.yml up -d identityserver fastapi-app

# Wait for services to be ready
echo "⏳ Waiting 30 seconds for services to start..."
sleep 30
echo "✅ Services should be ready"

# Run tests
echo "🧪 Running integration tests..."
docker-compose -f docker-compose.test.yml run --rm test-runner

# Capture exit code
TEST_EXIT_CODE=$?

# Show logs if tests failed
if [ $TEST_EXIT_CODE -ne 0 ]; then
    echo ""
    echo "❌ Tests failed! Showing service logs:"
    echo "========================================="
    echo ""
    echo "Identity Server logs:"
    docker-compose -f docker-compose.test.yml logs identityserver
    echo ""
    echo "FastAPI App logs:"
    docker-compose -f docker-compose.test.yml logs fastapi-app
fi

# Clean up
echo ""
echo "🧹 Cleaning up..."
docker-compose -f docker-compose.test.yml down -v

# Exit with test exit code
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo ""
    echo "================================================"
    echo "✅ All tests passed!"
    echo "================================================"
else
    echo ""
    echo "================================================"
    echo "❌ Tests failed!"
    echo "================================================"
fi

exit $TEST_EXIT_CODE
