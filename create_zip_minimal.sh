#!/bin/bash
# Create a minimal zip file WITHOUT model files (for code sharing only)

ZIP_NAME="semicomplete_code_only.zip"
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
    # Exclude model files
    "*/container_final_model/*"
    "*/container_model/*"
    "*/network_model/*"
    "*/sqli_benign_xss/model_output/*"
    "*.safetensors"
    "*.bin"
    "*.pt"
    "*.pth"
)

echo "📦 Creating MINIMAL zip file (code only, no models): $ZIP_NAME"
echo "📊 Excluding: venv/, models, __pycache__/, .git/, etc."
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
echo "   - Configuration files"
echo "   - Dockerfiles and docker-compose.yml"
echo ""
echo "🚫 Excluded:"
echo "   - Model files (users need to train their own)"
echo "   - Virtual environments (venv/)"
echo "   - Python cache (__pycache__/)"
echo "   - Git history (.git/)"
echo "   - ChromaDB data (chroma_db/)"
echo ""
echo "💡 Note: Recipients will need to train models using the notebooks in slm/"

