from fastapi import FastAPI, File, HTTPException
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
import uvicorn
import os
import asyncio
import hashlib
import json
import datetime
import mimetypes
import platform
import psutil
import logging
import signal
import sys
import shutil  # For checking binary existence
import textwrap

# Import tunnel tools from tunnel_tools.py
from tunnel_tools import tunnel_tools

# ---------------- Global Constants and Variables ---------------- #
ENABLE_PCAP = False         # Set to True to enable PCAP capturing (stubbed)
ENABLE_LOGGING = True         # Enable detailed logging
PORT = 3000
INPUT_FILES_DIR = os.path.join(os.path.dirname(__file__), "input_files")
os.makedirs(INPUT_FILES_DIR, exist_ok=True)
active_tunnel = None

# Global list to track child processes (if needed)
child_processes = []

# ---------------- Logging Setup ---------------- #
try:
    import colorlog
    handler = colorlog.StreamHandler()
    formatter = colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            'DEBUG':    'cyan',
            'INFO':     'green',
            'WARNING':  'yellow',
            'ERROR':    'red',
            'CRITICAL': 'bold_red',
        }
    )
    handler.setFormatter(formatter)
    logger = colorlog.getLogger("epic_server")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
except ImportError:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger("epic_server")

# ---------------- FastAPI Lifespan ---------------- #
from contextlib import asynccontextmanager
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🚀 Server startup")
    yield
    # Shutdown: try stopping any active tunnel
    if active_tunnel:
        logger.info("🛑 Shutting down active tunnel")
        try:
            await asyncio.get_event_loop().run_in_executor(None, active_tunnel.stop)
        except Exception as e:
            logger.error(f"Error stopping active tunnel during shutdown: {str(e)}")
    logger.info("🛑 Server shutdown")

app = FastAPI(
    title="Epic Tunnel Tools Server",
    description="An academically inclined, optimized server that integrates advanced tunnel tools.",
    version="1.0",
    lifespan=lifespan
)

# ---------------- Signal Handling ---------------- #
def kill_child_processes():
    for proc in child_processes:
        try:
            proc.kill()
        except Exception:
            pass

def signal_handler(sig, frame):
    logger.info("Ctrl+C detected. Terminating all child processes and shutting down gracefully.")
    kill_child_processes()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ---------------- Helper Functions ---------------- #
def calculate_file_hash(file_path: str) -> str:
    """Compute SHA-256 hash of a file for integrity verification."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def get_file_metadata(file_path: str) -> dict:
    """Return metadata for a file."""
    stats = os.stat(file_path)
    file_hash = calculate_file_hash(file_path)
    content_type, _ = mimetypes.guess_type(file_path)
    if content_type is None:
        content_type = "application/octet-stream"
    return {
        "filename": os.path.basename(file_path),
        "size": stats.st_size,
        "hash": file_hash,
        "contentType": content_type,
        "timestamp": datetime.datetime.fromtimestamp(stats.st_mtime).isoformat()
    }

# ---------------- API Endpoints ---------------- #
@app.post("/start-tunnel")
async def start_tunnel(payload: dict):
    """
    Start a tunnel using the specified tool.
    Payload must include "toolName".
    """
    global active_tunnel
    tool_name = payload.get("toolName")
    if not tool_name:
        raise HTTPException(status_code=400, detail="toolName is required.")
    # Optionally check if tool binary exists (if applicable)
    # if not shutil.which(tool_name):
    #     raise HTTPException(status_code=500, detail=f"Binary for {tool_name} not found.")
    tool = next((t for t in tunnel_tools if t.name.lower() == tool_name.lower()), None)
    if not tool:
        raise HTTPException(status_code=400, detail=f"Invalid tool name: {tool_name}")
    try:
        if active_tunnel:
            logger.info("An active tunnel exists. Stopping it before starting a new one.")
            await asyncio.get_event_loop().run_in_executor(None, active_tunnel.stop)
        loop = asyncio.get_event_loop()
        url = await loop.run_in_executor(None, tool.start, {"port": PORT})
        active_tunnel = tool
        logger.info(f"✅ Tunnel started successfully with URL: {url}")
        return JSONResponse({"url": url})
    except Exception as e:
        logger.error(f"❌ Failed to start tunnel: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start tunnel: {str(e)}")

@app.post("/stop-tunnel")
async def stop_tunnel():
    """
    Stop the currently active tunnel.
    Returns 200 even if no tunnel is active.
    """
    global active_tunnel
    if active_tunnel:
        try:
            await asyncio.get_event_loop().run_in_executor(None, active_tunnel.stop)
            active_tunnel = None
            logger.info("✅ Tunnel stopped successfully.")
            return JSONResponse({"message": "Tunnel stopped"})
        except Exception as e:
            logger.error(f"❌ Failed to stop tunnel: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to stop tunnel: {str(e)}")
    else:
        logger.info("⚠️ No active tunnel to stop.")
        return JSONResponse({"message": "No active tunnel"})

@app.get("/files")
async def list_files():
    """
    List all files in the input_files directory along with their metadata.
    """
    try:
        files = os.listdir(INPUT_FILES_DIR)
        files_metadata = [get_file_metadata(os.path.join(INPUT_FILES_DIR, f)) for f in files]
        return JSONResponse(files_metadata)
    except Exception as e:
        logger.error(f"❌ Failed to list files: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list files: {str(e)}")

@app.get("/download/{filename}")
async def download_file(filename: str):
    """
    Download a specified file with integrity metadata in headers.
    """
    file_path = os.path.join(INPUT_FILES_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found.")
    metadata = get_file_metadata(file_path)
    headers = {
        "Content-Type": metadata["contentType"],
        "X-File-Metadata": json.dumps(metadata),
        "X-File-Hash": metadata["hash"],
        "X-File-Size": str(metadata["size"])
    }
    return FileResponse(file_path, headers=headers, media_type=metadata["contentType"], filename=filename)

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return JSONResponse({"status": "ok", "timestamp": datetime.datetime.now().isoformat()})

@app.get("/diagnostics")
async def diagnostics():
    """Return system diagnostics for academic monitoring."""
    try:
        diagnostics_data = {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory": psutil.virtual_memory()._asdict(),
            "timestamp": datetime.datetime.now().isoformat()
        }
        return JSONResponse(diagnostics_data)
    except Exception as e:
        logger.error(f"❌ Failed to get diagnostics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get diagnostics: {str(e)}")

@app.post("/upload-test")
async def upload_test(file: bytes = File(...)):
    """Test file upload and report its size."""
    if not file:
        raise HTTPException(status_code=400, detail="No file data received")
    logger.info(f"Received file data of length: {len(file)}")
    return JSONResponse({"message": "File processed successfully", "fileSize": len(file)})

@app.get("/webtest")
async def webtest():
    """Serve a heavy HTML page for stress testing."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Heavy Web Test Page</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css">
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          .content-block { height: 300px; background-color: #e0e0e0; margin: 20px 0; }
        </style>
      </head>
      <body>
        <h1 class="text-center">Heavy Web Test Page</h1>
        <img src="https://picsum.photos/1920/1080" alt="High-Resolution Image 1" class="img-fluid">
        <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
        <video controls class="w-100">
          <source src="https://media.w3.org/2010/05/sintel/trailer_hd.mp4" type="video/mp4">
          Your browser does not support the video tag.
        </video>
        <div class="content-block"></div>
        <div class="content-block"></div>
        <div class="content-block"></div>
        <div class="content-block"></div>
        <img src="https://picsum.photos/1920/1080?random=2" alt="High-Resolution Image 2" class="img-fluid">
        <script>
          const heavyComputation = () => {
            const array = Array(100000).fill().map((_, i) => i * Math.random());
            return _.shuffle(array);
          };
          heavyComputation();
        </script>
        <p class="text-center">This page simulates a heavy load for real-world testing.</p>
      </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# ---------------- PCAP Capturing (Stubbed) ---------------- #
@app.on_event("startup")
async def startup_event():
    if ENABLE_PCAP:
        logger.info("Starting PCAP capture (simulated).")
        asyncio.create_task(dummy_pcap_capture())

async def dummy_pcap_capture():
    while True:
        logger.info("PCAP capture running (simulation).")
        await asyncio.sleep(24 * 60 * 60)

if __name__ == '__main__':
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=False)

