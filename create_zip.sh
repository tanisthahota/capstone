#!/bin/bash
# Create a compressed zip file excluding large unnecessary files

ZIP_NAME="semicomplete_threat_detection1.zip"
EXCLUDE_PATTERNS=(
    "*/venv/*"
    "*/__pycache__/*"
    "*/.git/*"
    "*/node_modules/*"
    "*/chroma_db/*"
    "*.pyc"
    "*.pyo"
    "*.log"
    "*/.DS_Store"
    "*/Thumbs.db"
)

echo "📦 Creating zip file: $ZIP_NAME"
echo "📊 Excluding: venv/, __pycache__/, .git/, chroma_db/, logs, etc."
echo ""

# Build exclude arguments
EXCLUDE_ARGS=()
for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    EXCLUDE_ARGS+=(-x "$pattern")
done

# Create zip with exclusions
zip -r "$ZIP_NAME" . "${EXCLUDE_ARGS[@]}" > /dev/null 2>&1

# Get size
SIZE=$(du -h "$ZIP_NAME" | cut -f1)
echo "✅ Created: $ZIP_NAME ($SIZE)"
echo ""
echo "📋 Included:"
echo "   - All source code (.py, .js, .yml files)"
echo "   - Model files (needed for detection)"
echo "   - Configuration files"
echo ""
echo "🚫 Excluded:"
echo "   - Virtual environments (venv/)"
echo "   - Python cache (__pycache__/)"
echo "   - Git history (.git/)"
echo "   - ChromaDB data (chroma_db/)"
echo "   - Log files"

