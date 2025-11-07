from fastapi import FastAPI, HTTPException, UploadFile, status, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import os
import json
import uuid
from datetime import datetime

# Import modules
from modules.extract_domains_api import fetch_domains, extract_unique_domains
from modules.domain_lead_finder import find_leads

app = FastAPI(
    title="Domain Tools API",
    description="Complete FastAPI server for modular domain extraction and lead finding tools",
    version="1.0.0",
)

# Enable CORS for frontend dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure data directory exists
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
os.makedirs(DATA_DIR, exist_ok=True)


# Pydantic models
class NamekartRequest(BaseModel):
    token: str
    size: Optional[int] = 200


class LeadRequestModel(BaseModel):
    domains: List[str]
    debug: Optional[bool] = False


class JSONExtractRequest(BaseModel):
    json_data: dict
    domains: List[str]
    key: Optional[str] = None


# Helper function to generate unique filenames
def generate_filename(prefix: str, extension: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_id = str(uuid.uuid4())[:8]
    return f"{prefix}_{timestamp}_{unique_id}.{extension}"


# 0. Hello endpoint for testing
@app.get("/hello")
async def hello():
    """Simple hello endpoint for testing."""
    return {
        "message": "Hello from Domain Tools API!",
        "status": "ready",
        "endpoints": 5,
    }


# 1. Extract domains from Namekart API
@app.post("/api/extract-namekart")
async def extract_namekart(request: NamekartRequest):
    """Extract domains from Namekart dashboard API."""
    try:
        # Fetch data from API
        api_data = fetch_domains(request.token, request.size)
        if api_data is None:
            raise HTTPException(
                status_code=400, detail="Failed to fetch data from Namekart API"
            )

        # Extract unique domains
        domains = extract_unique_domains(api_data)

        # Save results to data directory
        output_file = generate_filename("namekart_domains", "txt")
        output_path = os.path.join(DATA_DIR, output_file)

        with open(output_path, "w") as f:
            for domain in domains:
                f.write(f"{domain}\n")

        # Also save raw API data for reference
        json_file = generate_filename("namekart_raw", "json")
        json_path = os.path.join(DATA_DIR, json_file)

        with open(json_path, "w") as f:
            json.dump(api_data, f, indent=2)

        return {
            "success": True,
            "domains": domains,
            "count": len(domains),
            "output_file": output_file,
            "raw_data_file": json_file,
            "message": f"Successfully extracted {len(domains)} domains from Namekart API",
        }

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error processing Namekart API: {str(e)}"
        )


# 4.1 Find leads for single domain
@app.get("/api/find-leads")
async def find_lead_for_single(domain: str, debug: bool = False):
    """
    Find potential leads for a single domain.
    Usage: /api/find-leads?domain=apex.com
    """
    try:
        leads_dict = find_leads([domain])
        leads = leads_dict.get(domain, [])
        return {
            "success": True,
            "leads": leads,  # This is a list of {domain, url}
            "count": len(leads),
            "domain": domain,
            "message": f"Lead search completed for {domain}",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


# 4.2 Find leads for domain.txt file
@app.post("/api/find-leads")
async def find_leads_from_file(file: UploadFile = File(...), debug: bool = Form(False)):
    """
    Upload a .txt file with one domain per line.
    """
    input_path = None
    try:
        input_name = f"temp_{uuid.uuid4().hex}_{file.filename}"
        input_path = os.path.join(DATA_DIR, input_name)
        with open(input_path, "wb") as f:
            f.write(await file.read())

        with open(input_path, "r", encoding="utf-8") as f:
            domains = [line.strip() for line in f if line.strip()]

        os.remove(input_path)
        input_path = None

        if not domains:
            raise HTTPException(status_code=400, detail="No domains found in file.")

        leads_dict = find_leads(domains)
        # leads_dict: { input_domain: [ {domain, url}, ... ], ... }

        return {
            "success": True,
            "leads": leads_dict,
            "count": len(domains),
            "domains": domains,
            "message": f"Lead search completed for {len(domains)} domains",
        }

    except Exception as e:
        if input_path and os.path.exists(input_path):
            try:
                os.remove(input_path)
            except:
                pass
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")


# 5. Health check
@app.get("/api/health")
def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "message": "All systems operational",
        "data_dir": DATA_DIR,
        "endpoints_active": 6,
    }


# 6. List files in data directory
@app.get("/api/files")
def list_data_files():
    """List files in the data directory."""
    try:
        files = []
        for filename in os.listdir(DATA_DIR):
            filepath = os.path.join(DATA_DIR, filename)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                files.append(
                    {
                        "filename": filename,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    }
                )
        return {"files": files, "count": len(files)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error listing files: {str(e)}")


# 7. Clean up the files in data directory
@app.delete("/api/clear-files")
def clear_data_files():
    """
    Delete all files in the data directory.
    """
    try:
        deleted = []
        for filename in os.listdir(DATA_DIR):
            filepath = os.path.join(DATA_DIR, filename)
            if os.path.isfile(filepath):
                os.remove(filepath)
                deleted.append(filename)
        return {
            "success": True,
            "deleted_files": deleted,
            "count": len(deleted),
            "message": f"Cleared {len(deleted)} file(s) from data directory.",
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting files: {str(e)}",
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
