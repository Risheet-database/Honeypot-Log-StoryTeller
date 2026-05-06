from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from shared.minio_utils import minio_client

router = APIRouter(prefix="/download", tags=["download"])

@router.get("/{file_type}/{session_id}")
def download_file(file_type: str, session_id: str):
    allowed_types = {"pdf": ".pdf", "json": ".json", "stix": "_stix.json"}
    if file_type not in allowed_types:
        raise HTTPException(status_code=400, detail="Invalid file type. Use pdf, json, or stix.")
        
    object_name = f"{session_id}{allowed_types[file_type]}"
    bucket_name = "d5-reports"
    
    try:
        response = minio_client.client.get_object(bucket_name, object_name)
        
        media_type = "application/pdf" if file_type == "pdf" else "application/json"
        
        return StreamingResponse(
            response.stream(32*1024), 
            media_type=media_type,
            headers={"Content-Disposition": f"attachment; filename={object_name}"}
        )
    except Exception as e:
        raise HTTPException(status_code=404, detail=f"Report not found: {str(e)}")
