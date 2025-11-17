#!/bin/bash
# Setup kernel tuning for high-throughput multicast relay
# Run this before performance testing

set -e

echo "=== Current Kernel Network Buffer Settings ==="
echo "Send buffers:"
sysctl net.core.wmem_max net.core.wmem_default
echo ""
echo "Receive buffers:"
sysctl net.core.rmem_max net.core.rmem_default
echo ""

# Check if we need to increase limits
WMEM_MAX=$(sysctl -n net.core.wmem_max)
REQUIRED_WMEM=16777216  # 16 MB

if [ "$WMEM_MAX" -lt "$REQUIRED_WMEM" ]; then
    echo "⚠️  WARNING: wmem_max ($WMEM_MAX) is less than required ($REQUIRED_WMEM)"
    echo ""
    echo "Applying recommended kernel tuning..."
    echo "(This requires root privileges)"
    echo ""

    sudo sysctl -w net.core.wmem_max=16777216      # 16 MB max send buffer
    sudo sysctl -w net.core.wmem_default=4194304   # 4 MB default send buffer
    sudo sysctl -w net.core.rmem_max=16777216      # 16 MB max receive buffer
    sudo sysctl -w net.core.rmem_default=4194304   # 4 MB default receive buffer

    echo ""
    echo "✅ Kernel tuning applied (session only)"
    echo ""
    echo "To make permanent, add to /etc/sysctl.conf:"
    echo "  net.core.wmem_max = 16777216"
    echo "  net.core.wmem_default = 4194304"
    echo "  net.core.rmem_max = 16777216"
    echo "  net.core.rmem_default = 4194304"
    echo ""
else
    echo "✅ Kernel buffer limits are sufficient"
    echo ""
fi

echo "=== Final Settings ==="
sysctl net.core.wmem_max net.core.wmem_default
sysctl net.core.rmem_max net.core.rmem_default
echo ""
echo "Ready for high-throughput testing!"
