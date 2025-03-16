from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import asyncio
import logging
import sys
import signal
import uvicorn

# Import one of our tunnel tools as an integration test.
from tunnel_tools import NgrokTunnel

# Set up basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("integration_server")

# Global list for tracking child processes (if needed)
child_processes = []

# Signal handler to ensure graceful termination.
def signal_handler(sig, frame):
    logger.info("Ctrl+C pressed. Exiting gracefully...")
    # Here you could iterate child_processes and kill them.
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

app = FastAPI(
    title="Integration Test Server for Tunnel Tools",
    description="A minimal academic integration test to verify that the server correctly calls the new tools module.",
    version="1.0"
)

@app.get("/test-tunnel")
async def test_tunnel():
    """
    This endpoint is used to verify that our server can call our tools.py properly.
    It instantiates a NgrokTunnel, starts it asynchronously, and then stops it.
    """
    tool = NgrokTunnel()
    loop = asyncio.get_event_loop()
    try:
        # Run the blocking start() function in a thread pool.
        tunnel_url = await loop.run_in_executor(None, tool.start, {"port": 3000})
        logger.info(f"Integration test: Tunnel started with URL: {tunnel_url}")
        # Stop the tunnel after obtaining the URL.
        await loop.run_in_executor(None, tool.stop)
        return JSONResponse({"tunnel_url": tunnel_url})
    except Exception as e:
        logger.error(f"Integration test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return JSONResponse({"status": "ok"})

if __name__ == '__main__':
    # Run the server on port 3000.
    uvicorn.run("integration_server:app", host="0.0.0.0", port=3000, reload=False)
