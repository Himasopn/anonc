import os
import sys
import uvicorn

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api.index import app

if __name__ == "__main__":
    print("=" * 60)
    print("  anonc • Cloud Workspace by ascloud")
    print("  Running locally on: http://127.0.0.1:8000")
    print("=" * 60)
    uvicorn.run("api.index:app", host="127.0.0.1", port=8000, reload=False)
