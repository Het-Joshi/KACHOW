#!/usr/bin/env python3
"""
client.py

An academically oriented client for measuring tunnel performance,
file transfers, diagnostics, and web tests via a server that manages tunnels.
This script integrates advanced measurement features for international research,
using asynchronous httpx calls, Playwright for front-end metrics, and tqdm for progress.

Requirements:
  pip install requests tqdm playwright httpx psutil
  python -m playwright install

Author: [Your Name]
Date: 2025-03-15
"""

import asyncio
import json
import os
import hashlib
import sys
import time
import datetime
import logging
import argparse
import tempfile
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from tqdm import tqdm
import httpx
from playwright.async_api import async_playwright, Browser
# Import tunnel tools from tunnel_tools.py
from tunnel_tools import tunnel_tools

# ---------------- Global Constants ---------------- #
TOR_SOCKS_PORT = 9050
TOR_SOCKS_HOST = '127.0.0.1'
SERVER_HOST = '209.38.108.22'
SERVER_PORT = 3000
SERVER_URL = f'http://{SERVER_HOST}:{SERVER_PORT}'
ENABLE_LOGGING = True
ENABLE_PCAP = False  # Stubbed
NUM_MEASUREMENTS = 1

TEMP_DIR = os.path.join(os.path.abspath(os.path.expanduser("~")), "client_temp")
RESULTS_DIR = os.path.join(os.getcwd(), "results")
os.makedirs(TEMP_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# ---------------- Logging Setup ---------------- #
logging.basicConfig(
    level=logging.INFO if ENABLE_LOGGING else logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ---------------- Data Classes ---------------- #
@dataclass
class Timing:
    duration: float  # in ms

@dataclass
class DiagnosticResult:
    tool: str
    rawOutput: str
    parsedOutput: Any
    timing: Timing
    error: Optional[str] = None

@dataclass
class CurlResult:
    status_code: int
    time_split: Dict[str, float]
    ttfb: float
    latency: float
    size_download: int
    speed_download: float
    speed_upload: float
    error: Optional[str] = None

@dataclass
class FileTransferResult:
    filename: str
    timestamp: float
    original_metadata: Dict[str, Any]
    received_metadata: Dict[str, Any]
    transfer_success: bool
    hash_match: bool
    metadata_match: bool
    server_hash: str
    client_hash: str
    hash_match_details: Dict[str, Any]
    size_match: bool
    transfer_stats: CurlResult
    percent_downloaded: float
    error: Optional[str] = None

@dataclass
class WebTestResult:
    url: str
    status_code: int
    speed_download: float
    speed_upload: float
    time_split: Dict[str, float]
    fcp: float
    lcp: float
    error: Optional[str] = None

@dataclass
class Measurement:
    measurement_number: int
    timestamp: float
    file_transfers: Dict[str, FileTransferResult]
    web_tests: List[WebTestResult]

@dataclass
class RunResult:
    tool: str
    diagnostics: List[Dict]  # Stubbed diagnostics data
    measurements: List[Measurement]
    durations: Dict[str, Any]
    pcap_file_path: Optional[str] = None
    all_downloads_complete: bool = True
    errors: List[Dict[str, str]] = None

# ---------------- Utility Classes and Functions ---------------- #
class Stopwatch:
    def __init__(self):
        self.start_time = 0.0
        self.end_time = 0.0

    def start(self):
        self.start_time = time.perf_counter()

    def stop(self):
        self.end_time = time.perf_counter()

    def get_timing(self) -> Timing:
        return Timing(duration=(self.end_time - self.start_time) * 1000)

async def run_command(command: str, args: List[str]) -> Dict[str, Any]:
    """Run a subprocess command asynchronously and return its output."""
    proc = await asyncio.create_subprocess_exec(
        command, *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return {
        'stdout': stdout.decode(),
        'stderr': stderr.decode(),
        'code': proc.returncode
    }

class Curl:
    """Parser for curl output to extract transfer metrics."""
    def parse(self, output: str) -> CurlResult:
        result = CurlResult(
            status_code=0,
            time_split={
                'dns_lookup': 0.0,
                'tcp_connection': 0.0,
                'tls_handshake': 0.0,
                'first_byte': 0.0,
                'total': 0.0
            },
            ttfb=0.0,
            latency=0.0,
            size_download=0,
            speed_download=0.0,
            speed_upload=0.0
        )
        for line in output.split('\n'):
            if ': ' in line:
                key, value = line.split(': ', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                if key == 'http_code':
                    result.status_code = int(value)
                elif key in result.time_split:
                    result.time_split[key] = float(value) * 1000
                elif key == 'download_speed':
                    result.speed_download = float(value)
                elif key == 'upload_speed':
                    result.speed_upload = float(value)
                elif key == 'size_of_download':
                    result.size_download = int(value)
        result.ttfb = sum(result.time_split.values())
        result.latency = result.time_split['tcp_connection']
        return result

async def perform_web_test(url: str) -> WebTestResult:
    """Perform a web test using curl for network timings and Playwright for front-end metrics."""
    is_onion = '.onion' in url
    curl_args = [
        '-w',
        ('DNS Lookup: %{time_namelookup}\n'
         'TCP Connection: %{time_connect}\n'
         'TLS Handshake: %{time_appconnect}\n'
         'Start Transfer: %{time_starttransfer}\n'
         'Total Time: %{time_total}\n'
         'Download Speed: %{speed_download}\n'
         'Upload Speed: %{speed_upload}\n'
         'HTTP Code: %{http_code}\n'
         'Size of Download: %{size_download}\n'),
        '-o', '/dev/null',
        '-s'
    ]
    if is_onion:
        curl_args.extend(['--socks5-hostname', f'{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}', '--insecure'])
    curl_args.append(url)
    curl_out = await run_command('curl', curl_args)
    curl_result = Curl().parse(curl_out['stdout'])

    fcp, lcp, error = 0.0, 0.0, None
    try:
        async with async_playwright() as p:
            browser: Browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(url, wait_until='load')
            metrics = await page.evaluate('''
                () => new Promise((resolve) => {
                    const observer = new PerformanceObserver((list) => {
                        const entries = list.getEntries();
                        let fcp = 0, lcp = 0;
                        for (const entry of entries) {
                            if (entry.name === 'first-contentful-paint') fcp = entry.startTime;
                            if (entry.entryType === 'largest-contentful-paint') lcp = entry.startTime;
                        }
                        resolve({fcp, lcp});
                    });
                    observer.observe({type: 'paint', buffered: true});
                    observer.observe({type: 'largest-contentful-paint', buffered: true});
                    setTimeout(() => {
                        resolve({
                            fcp: performance.getEntriesByName('first-contentful-paint')[0]?.startTime || 0,
                            lcp: performance.getEntriesByType('largest-contentful-paint')[0]?.startTime || 0
                        });
                    }, 3000);
                })
            ''')
            fcp = metrics['fcp']
            lcp = metrics['lcp']
            await browser.close()
    except Exception as e:
        error = f"Playwright error: {str(e)}"
    return WebTestResult(
        url=url,
        status_code=curl_result.status_code,
        speed_download=curl_result.speed_download,
        speed_upload=curl_result.speed_upload,
        time_split=curl_result.time_split,
        fcp=fcp,
        lcp=lcp,
        error=error or curl_result.error
    )

async def perform_file_transfer(url: str, filename: str, original_metadata: Dict[str, Any]) -> FileTransferResult:
    """Download a file using curl, calculate its SHA256 hash, and verify its integrity."""
    transfer_start = time.perf_counter() * 1000
    temp_file = os.path.join(TEMP_DIR, f"{int(time.time()*1000)}-{filename}")
    logger.info(f"Downloading {url} to {temp_file}")
    curl_args = [
        '-w',
        ('DNS Lookup: %{time_namelookup}\n'
         'TCP Connection: %{time_connect}\n'
         'TLS Handshake: %{time_appconnect}\n'
         'Start Transfer: %{time_starttransfer}\n'
         'Total Time: %{time_total}\n'
         'Download Speed: %{speed_download}\n'
         'Upload Speed: %{speed_upload}\n'
         'HTTP Code: %{http_code}\n'
         'Size of Download: %{size_download}\n'),
        '-D', '-',
        '-o', temp_file,
        '-s'
    ]
    if '.onion' in url:
        curl_args.extend(['--socks5-hostname', f'{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}', '--insecure'])
    curl_args.append(url)
    curl_out = await run_command('curl', curl_args)
    lines = curl_out['stdout'].splitlines()
    time_split = {
        'dns_lookup': float(next((line.split(': ')[1] for line in lines if "DNS Lookup" in line), "0")) * 1000,
        'tcp_connection': float(next((line.split(': ')[1] for line in lines if "TCP Connection" in line), "0")) * 1000,
        'tls_handshake': float(next((line.split(': ')[1] for line in lines if "TLS Handshake" in line), "0")) * 1000,
        'first_byte': float(next((line.split(': ')[1] for line in lines if "Start Transfer" in line), "0")) * 1000,
        'total': float(next((line.split(': ')[1] for line in lines if "Total Time" in line), "0")) * 1000
    }
    curl_result = Curl().parse(curl_out['stdout'])
    percent_downloaded = (curl_result.size_download / original_metadata['size'] * 100) if original_metadata['size'] > 0 else 0

    hash_start = time.perf_counter() * 1000
    with open(temp_file, "rb") as f:
        client_hash = hashlib.sha256(f.read()).hexdigest()
    hash_end = time.perf_counter() * 1000

    transfer_success = curl_result.status_code == 200
    size_match = os.path.getsize(temp_file) == original_metadata['size']
    hash_match = client_hash == original_metadata['hash']

    received_metadata = {
        'filename': filename,
        'size': os.path.getsize(temp_file),
        'hash': client_hash,
        'contentType': original_metadata['contentType'],
        'timestamp': datetime.datetime.now().isoformat()
    }
    try:
        os.remove(temp_file)
    except Exception:
        pass

    return FileTransferResult(
        filename=filename,
        timestamp=transfer_start,
        original_metadata=original_metadata,
        received_metadata=received_metadata,
        transfer_success=transfer_success,
        hash_match=hash_match,
        metadata_match=hash_match and size_match,
        server_hash=original_metadata['hash'],
        client_hash=client_hash,
        hash_match_details={
            'matched': hash_match,
            'server_hash': original_metadata['hash'],
            'client_hash': client_hash,
            'time_taken': hash_end - hash_start
        },
        size_match=size_match,
        transfer_stats=curl_result,
        percent_downloaded=percent_downloaded,
        error=None
    )

async def run_diagnostic_tool(tool: str, args: List[str]) -> DiagnosticResult:
    """Run a diagnostic tool (e.g., dig) and capture its output and timing."""
    stopwatch = Stopwatch()
    stopwatch.start()
    proc_output = await run_command(tool, args)
    stopwatch.stop()
    parsed = None
    if tool == "dig":
        parsed = {"raw": proc_output["stdout"]}
    return DiagnosticResult(
        tool=tool,
        rawOutput=proc_output["stdout"],
        parsedOutput=parsed,
        timing=stopwatch.get_timing(),
        error=None
    )

async def perform_measurements_run(tunnel_tool_name: str, enable_pcap: bool, num_measurements: int) -> RunResult:
    total_stopwatch = Stopwatch()
    setup_stopwatch = Stopwatch()
    diagnostics_stopwatch = Stopwatch()

    total_stopwatch.start()
    setup_stopwatch.start()

    errors = []
    all_downloads_complete = True

    # Fetch file metadata from server
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f'{SERVER_URL}/files')
            available_files = response.json()
            logger.info(f"ðŸ“ Fetched metadata for {len(available_files)} files")
        except Exception as e:
            errors.append({'stage': 'File Metadata Fetch', 'error': str(e)})
            available_files = []

    # Start tunnel via server
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(f'{SERVER_URL}/start-tunnel', json={'toolName': tunnel_tool_name})
            if response.status_code != 200:
                raise Exception(response.json().get('detail', 'Unknown error'))
            tunnel_url = response.json().get('url', '').rstrip('/')
            logger.info(f"âœ… Tunnel started: {tunnel_url}")
    except Exception as e:
        errors.append({'stage': 'Tunnel Setup', 'error': str(e)})
        tunnel_url = ""
    if not tunnel_url:
        errors.append({'stage': 'Tunnel Setup', 'error': 'Tunnel URL is empty or invalid'})

    # PCAP capture (stubbed)
    pcap_file_path = None
    if enable_pcap:
        pcap_file_path = f"client_capture_{tunnel_tool_name}_{datetime.date.today()}.pcap"
        logger.info(f"PCAP capture started (stub), saving to {pcap_file_path}")

    setup_stopwatch.stop()
    logger.info("â³ Waiting 10 seconds for tunnel stabilization...")
    await asyncio.sleep(10)

    # Diagnostics Stage (skip for .onion)
    diagnostics = []
    diagnostics_stopwatch.start()
    if tunnel_url and ".onion" not in tunnel_url:
        try:
            from urllib.parse import urlparse
            domain = urlparse(tunnel_url).hostname
            diagnostics.append(await run_diagnostic_tool("dig", [domain]))
        except Exception as e:
            errors.append({'stage': 'Diagnostics', 'error': str(e)})
            diagnostics.append({
                "tool": "dig",
                "rawOutput": "",
                "parsedOutput": None,
                "timing": {"duration": 0},
                "error": str(e)
            })
    else:
        logger.info("Skipping diagnostics for .onion tunnel")
    diagnostics_stopwatch.stop()

    # Measurements Stage
    measurements = []
    total_measurement_duration = 0.0
    for i in tqdm(range(num_measurements), desc=f"Measurements for {tunnel_tool_name}"):
        meas_stopwatch = Stopwatch()
        meas_stopwatch.start()
        measurement_start = time.perf_counter() * 1000

        file_transfers = {}
        web_tests = []

        if tunnel_url and available_files:
            for file_meta in available_files:
                try:
                    ft_result = await perform_file_transfer(
                        f'{tunnel_url}/download/{file_meta["filename"]}',
                        file_meta['filename'],
                        file_meta
                    )
                    file_transfers[file_meta['filename']] = ft_result
                    if not ft_result.transfer_success or not ft_result.hash_match:
                        all_downloads_complete = False
                except Exception as e:
                    errors.append({'stage': 'File Transfer', 'error': f"Failed to transfer {file_meta['filename']}: {str(e)}"})
                    all_downloads_complete = False

        try:
            wt_result = await perform_web_test(f'{tunnel_url}/webtest')
            web_tests.append(wt_result)
        except Exception as e:
            errors.append({'stage': 'Web Test', 'error': str(e)})

        meas_stopwatch.stop()
        total_measurement_duration += meas_stopwatch.get_timing().duration
        measurements.append(Measurement(
            measurement_number=i + 1,
            timestamp=measurement_start,
            file_transfers=file_transfers,
            web_tests=web_tests
        ))

    # Cleanup: Stop tunnel via server
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f'{SERVER_URL}/stop-tunnel')
            logger.info("âœ… Tunnel stopped successfully via server")
    except Exception as e:
        errors.append({'stage': 'Tunnel Cleanup', 'error': str(e)})

    total_stopwatch.stop()
    durations = {
        'total': {'duration': total_stopwatch.get_timing().duration},
        'toolSetup': {'duration': setup_stopwatch.get_timing().duration},
        'diagnostics': {'duration': diagnostics_stopwatch.get_timing().duration},
        'measurements': {
            'total': {'duration': total_measurement_duration},
            'average': {'duration': (total_measurement_duration / num_measurements) if num_measurements > 0 else 0}
        }
    }

    return RunResult(
        tool=tunnel_tool_name,
        diagnostics=diagnostics,
        measurements=measurements,
        durations=durations,
        pcap_file_path=pcap_file_path,
        all_downloads_complete=all_downloads_complete,
        errors=errors
    )

def flatten_results(result: RunResult) -> List[Dict[str, Any]]:
    """Flatten measurement results into a list of dictionaries for export."""
    flattened = []
    for meas in result.measurements:
        if meas.file_transfers:
            for fname, ft in meas.file_transfers.items():
                flattened.append({
                    "tool": result.tool,
                    "measurement_number": meas.measurement_number,
                    "timestamp": meas.timestamp,
                    "filename": fname,
                    "file_size": ft.original_metadata['size'],
                    "transfer_success": ft.transfer_success,
                    "status_code": ft.transfer_stats.status_code,
                    "download_speed": ft.transfer_stats.speed_download,
                    "upload_speed": ft.transfer_stats.speed_upload,
                    "dns_lookup": ft.transfer_stats.time_split['dns_lookup'],
                    "tcp_connection": ft.transfer_stats.time_split['tcp_connection'],
                    "tls_handshake": ft.transfer_stats.time_split['tls_handshake'],
                    "time_to_first_byte": ft.transfer_stats.time_split['first_byte'],
                    "total_transfer_time": ft.transfer_stats.time_split['total'],
                    "hash_match": ft.hash_match,
                    "size_match": ft.size_match,
                    "percent_downloaded": ft.percent_downloaded,
                    "error": ft.error
                })
        if meas.web_tests:
            for wt in meas.web_tests:
                flattened.append({
                    "tool": result.tool,
                    "measurement_number": meas.measurement_number,
                    "timestamp": meas.timestamp,
                    "url": wt.url,
                    "status_code": wt.status_code,
                    "download_speed": wt.speed_download,
                    "upload_speed": wt.speed_upload,
                    "dns_lookup": wt.time_split['dns_lookup'],
                    "tcp_connection": wt.time_split['tcp_connection'],
                    "tls_handshake": wt.time_split['tls_handshake'],
                    "time_to_first_byte": wt.time_split['first_byte'],
                    "total_time": wt.time_split['total'],
                    "fcp": wt.fcp,
                    "lcp": wt.lcp,
                    "error": wt.error
                })
    return flattened

async def save_results(directory: str, tool_name: str, result: RunResult):
    os.makedirs(directory, exist_ok=True)
    filename = f"{tool_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = os.path.join(directory, filename)
    flattened = flatten_results(result)
    with open(filepath, "w") as f:
        json.dump(flattened, f, indent=2, default=lambda o: o.__dict__)
    logger.info(f"Results saved to {filepath}")

async def main():
    parser = argparse.ArgumentParser(
        description="Client script for performing advanced measurements using tunnel tools."
    )
    parser.add_argument("--auto", action="store_true", help="Run in automatic mode across all tools")
    parser.add_argument("--num", type=int, default=NUM_MEASUREMENTS, help="Number of measurements per tool")
    args = parser.parse_args()

    results_dir = os.path.join(RESULTS_DIR, f"results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(results_dir, exist_ok=True)

    execution_times = []
    for tool in tqdm(tunnel_tools, desc="Tools Progress", unit="tool"):
        start_time = time.time()
        try:
            result = await perform_measurements_run(tool.name, ENABLE_PCAP, args.num)
            await save_results(results_dir, tool.name, result)
        except Exception as e:
            logger.error(f"Error with tool {tool.name}: {str(e)}")
        end_time = time.time()
        exec_time = end_time - start_time
        execution_times.append({"tool": tool.name, "time": exec_time})
        logger.info(f"{tool.name} executed in {exec_time:.2f} seconds")

    fastest = min(execution_times, key=lambda x: x["time"])
    slowest = max(execution_times, key=lambda x: x["time"])
    logger.info(f"Fastest tool: {fastest['tool']} ({fastest['time']:.2f} sec)")
    logger.info(f"Slowest tool: {slowest['tool']} ({slowest['time']:.2f} sec)")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Exiting gracefully.")
        sys.exit(0)

