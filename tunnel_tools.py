import subprocess
import logging
import time
import re
import requests
import os
import select
import argparse
import signal
import sys
from abc import ABC, abstractmethod
import textwrap


# ----------------- Global Process List & Safe Popen ----------------- #
child_processes = []

def safe_popen(*args, **kwargs):
    proc = subprocess.Popen(*args, **kwargs)
    child_processes.append(proc)
    return proc

# ----------------- Logging Setup ----------------- #
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
    logger = colorlog.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
except ImportError:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger()

# ----------------- Signal Handler ----------------- #
def signal_handler(sig, frame):
    logger.info("Ctrl+C pressed. Exiting gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ----------------- Helper Functions ----------------- #
def wait_for_pattern(process, pattern, timeout):
    """Wait for a regex pattern in process stdout or stderr within a timeout.
    Returns the regex match object if found; otherwise raises a TimeoutError."""
    regex = re.compile(pattern)
    start = time.monotonic()
    stdout = process.stdout
    stderr = process.stderr
    while True:
        for stream in (stdout, stderr):
            if stream is None:
                continue
            rlist, _, _ = select.select([stream], [], [], 0.1)
            if rlist:
                line = stream.readline()
                if line:
                    logger.debug(f"Output: {line.strip()}")
                    match = regex.search(line)
                    if match:
                        return match
        if time.monotonic() - start > timeout:
            raise TimeoutError(f"Timeout waiting for pattern: {pattern}")

def ensure_tor_running():
    """Ensure Tor is running. If not, attempt to start it."""
    try:
        subprocess.run(["pgrep", "tor"], check=True, stdout=subprocess.DEVNULL)
        logger.info("Tor service is already running.")
    except subprocess.CalledProcessError:
        logger.info("Tor is not running; attempting to start Tor service...")
        try:
            subprocess.run(["service", "tor", "start"], check=True)
            logger.info("Tor service started successfully.")
        except subprocess.CalledProcessError as e:
            raise Exception("Failed to start Tor service") from e

# ----------------- Base Tunnel Class ----------------- #
class BaseTunnel(ABC):
    def __init__(self):
        self.process = None
        self.pre_setup_commands = []  # Each command is a list of strings.
        self.pre_start_commands = []
        self.post_setup_commands = []

    def run_commands(self, commands):
        for cmd in commands:
            logger.info("Running command: " + " ".join(cmd))
            subprocess.run(cmd, check=True)

    def run_pre_setup_commands(self):
        if self.pre_setup_commands:
            self.run_commands(self.pre_setup_commands)

    def run_pre_start_commands(self):
        if self.pre_start_commands:
            self.run_commands(self.pre_start_commands)

    def run_post_setup_commands(self):
        if self.post_setup_commands:
            self.run_commands(self.post_setup_commands)

    def start(self, options=None):
        if options is None:
            options = {"port": 3000, "url_pattern": r"https://[^\s]+"}
        self.run_pre_setup_commands()
        self.run_pre_start_commands()
        port = options.get("port", 3000)
        logger.info(f"Starting {self.name} on port {port}")
        url = self.launch_tunnel(options)
        return url

    @abstractmethod
    def launch_tunnel(self, options) -> str:
        """Launch the tunnel and return the URL string."""
        pass

    def stop(self):
        if self.process:
            logger.info(f"Stopping {self.name}")
            self.process.kill()
            self.process = None

# ----------------- Tunnel Tool Implementations ----------------- #
class LocalTunnel(BaseTunnel):
    name = "LocalTunnel"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["lt", "--port", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, r"your url is: (https://[^\s]+)", 10)
            local_tunnel_url = match.group(1)
            logger.info(f"LocalTunnel URL: {local_tunnel_url}")
            password = self.get_tunnel_password()
            logger.info(f"Tunnel Password: {password}")
            return local_tunnel_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start LocalTunnel") from e

    def get_tunnel_password(self) -> str:
        try:
            response = requests.get("https://loca.lt/mytunnelpassword")
            return response.text.strip()
        except Exception as e:
            raise Exception("Could not retrieve tunnel password") from e

class CloudflareTunnel(BaseTunnel):
    name = "Cloudflared"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 8000)
        self.process = subprocess.Popen(
            ["cloudflared", "tunnel", "--url", f"http://localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, r"https?://[a-z0-9-]+\.trycloudflare\.com", 15)
            tunnel_url = match.group(0)
            logger.info(f"Cloudflare Tunnel URL: {tunnel_url}")
            return tunnel_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Cloudflare Tunnel") from e

class NgrokTunnel(BaseTunnel):
    name = "Ngrok"
    pre_setup_commands = [["echo", "Running pre-setup command for ngrok"]]
    pre_start_commands = [["echo", "Running pre-start command for ngrok"]]

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        url_pattern = options.get("url_pattern", r"https://[^\s]+")
        self.process = subprocess.Popen(
            ["ngrok", "http", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        time.sleep(10)  # Allow time for ngrok to initialize.
        try:
            resp = requests.get("http://127.0.0.1:4040/api/tunnels")
            data = resp.json()
            ngrok_url = data.get("tunnels", [{}])[0].get("public_url", "")
            if ngrok_url and re.match(url_pattern, ngrok_url):
                logger.info(f"Ngrok tunnel started with URL: {ngrok_url}")
                return ngrok_url
            else:
                raise Exception("Could not retrieve ngrok URL.")
        except Exception as e:
            raise Exception("Error fetching ngrok URL") from e

class ServeoTunnel(BaseTunnel):
    name = "Serveo"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["ssh", "-R", f"80:localhost:{port}", "serveo.net"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, r"Forwarding HTTP traffic from (https://[^\s]+)", 10)
            serveo_url = match.group(1)
            logger.info(f"Serveo URL: {serveo_url}")
            return serveo_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Serveo Tunnel") from e

class TelebitTunnel(BaseTunnel):
    name = "Telebit"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["pnpm", "dlx", "telebit", "http", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, r"Forwarding (https://[^\s]+) =>", 10)
            telebit_url = match.group(1)
            logger.info(f"Telebit URL: {telebit_url}")
            return telebit_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Telebit Tunnel") from e

class BoreTunnel(BaseTunnel):
    name = "Bore"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["bore", "local", str(port), "--to", "bore.pub"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        start = time.monotonic()
        try:
            while True:
                line = self.process.stdout.readline()
                if line:
                    words = line.split()
                    for word in words:
                        if word.startswith("bore.pub"):
                            bore_url = f"http://{word}"
                            logger.info(f"Bore URL: {bore_url}")
                            return bore_url
                if time.monotonic() - start > 5:
                    raise TimeoutError("Timeout waiting for Bore Tunnel URL")
        except Exception as e:
            raise Exception("Failed to start Bore Tunnel") from e

class LocalxposeTunnel(BaseTunnel):
    name = "Localxpose"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["pnpm", "dlx", "loclx", "tunnel", "http", "--to", f"localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, r"([a-z0-9]+\.loclx\.io)", 10)
            loclx_url = f"http://{match.group(1)}"
            logger.info(f"Localxpose URL: {loclx_url}")
            return loclx_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Localxpose Tunnel") from e

class ExposeTunnel(BaseTunnel):
    name = "Expose"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["expose", "share", f"http://localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, r"Public HTTPS:\s+(https://[^\s]+)", 10)
            expose_url = match.group(1)
            logger.info(f"Expose URL: {expose_url}")
            return expose_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Expose Tunnel") from e

class LoopholeTunnel(BaseTunnel):
    name = "Loophole"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["./loophole", "http", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, r"(https://[^\s]+) ->", 10)
            loophole_url = match.group(1)
            logger.info(f"Loophole URL: {loophole_url}")
            return loophole_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Loophole Tunnel") from e

class PinggyTunnel(BaseTunnel):
    name = "Pinggy"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["ssh", "-p", "443", "-R0:localhost:3000", "-L4300:localhost:4300", "qr@a.pinggy.io"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, r"(https://[^\s]+\.free\.pinggy\.link)", 10)
            pinggy_url = match.group(1)
            logger.info(f"Pinggy URL: {pinggy_url}")
            return pinggy_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Pinggy Tunnel") from e

class TailscaleTunnel(BaseTunnel):
    name = "Tailscale"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["sudo", "tailscale", "funnel", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, r"(https://[^\s]+\.ts\.net/)", 10)
            tailscale_url = match.group(1)
            logger.info(f"Tailscale URL: {tailscale_url}")
            return tailscale_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Tailscale Tunnel") from e

class TunnelPyjamas(BaseTunnel):
    name = "TunnelPyjamas"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        try:
            subprocess.run(["curl", f"https://tunnel.pyjam.as/{port}", "-o", "tunnel.conf"], check=True)
            os.chmod("tunnel.conf", 0o600)
        except subprocess.CalledProcessError as e:
            raise Exception("Failed to download tunnel configuration") from e
        self.process = subprocess.Popen(
            ["sudo", "wg-quick", "up", "./tunnel.conf"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, r"on (https://[^\s]+) ✨", 20)
            pyjamas_url = match.group(1).rstrip("/")
            logger.info(f"TunnelPyjamas URL: {pyjamas_url}")
            return pyjamas_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start TunnelPyjamas Tunnel") from e

    def stop(self):
        logger.info(f"Bringing down {self.name} tunnel.")
        try:
            subprocess.run(["sudo", "wg-quick", "down", "./tunnel.conf"], check=True, text=True)
            os.remove("tunnel.conf")
            logger.info(f"Stopped {self.name} tunnel.")
        except Exception as e:
            raise Exception("Failed to bring down TunnelPyjamas Tunnel") from e

class ZrokTunnel(BaseTunnel):
    name = "Zrok"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["./zrok", "share", "public", f"http://localhost:{port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, r"(https://[^\s]+)", 10)
            url = match.group(0).split("│")[0].strip()
            logger.info(f"Zrok URL: {url}")
            return url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Zrok Tunnel") from e

class TunwgTunnel(BaseTunnel):
    name = "Tunwg"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["./tunwg", "-p", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, r"(https://[^\s]+\.l\.tunwg\.com)", 10)
            tunwg_url = match.group(1)
            logger.info(f"Tunwg URL: {tunwg_url}")
            return tunwg_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Tunwg Tunnel") from e

class PacketriotTunnel(BaseTunnel):
    name = "Packetriot"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["sudo", "pktriot", "http", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, r"(\w+-\w+-\d+\.pktriot\.net)", 10)
            full_url = f"http://{match.group(1)}"
            logger.info(f"Packetriot URL: {full_url}")
            return full_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Packetriot Tunnel") from e

class BoreDigitalTunnel(BaseTunnel):
    name = "BoreDigital"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 8000)
        self.server = subprocess.Popen(
            ["./bore-server_linux_amd64"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        time.sleep(2)
        self.process = subprocess.Popen(
            ["./bore_linux_amd64", "-s", "bore.digital", "-p", "2200", "-ls", "localhost", "-lp", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, r"(https://[^\s]+bore\.digital[^\s]*)", 10)
            url = match.group(0).strip()
            logger.info(f"BoreDigital URL: {url}")
            return url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start BoreDigital Tunnel") from e

    def stop(self):
        if hasattr(self, "client") and self.client:
            self.client.kill()
        if hasattr(self, "server") and self.server:
            self.server.kill()
        logger.info(f"Stopped {self.name} tunnel.")

class LocalhostRunTunnel(BaseTunnel):
    name = "LocalhostRun"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["ssh", "-R", f"80:localhost:{port}", "nokey@localhost.run"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, r"(https://[^\s]+\.lhr\.life[^\s]*)", 10)
            url = match.group(0).strip()
            logger.info(f"Localhost.run URL: {url}")
            return url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Localhost.run Tunnel") from e

    def stop(self):
        super().stop()
        logger.info(f"Stopped {self.name} tunnel.")

class DevTunnel(BaseTunnel):
    name = "DevTunnel"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["devtunnel", "host", "-p", str(port), "--allow-anonymous"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        url_printed = False
        regex = re.compile(r"(https://[a-z0-9-]+\.inc1\.devtunnels\.ms(:\d+)?(?!-inspect))")
        start = time.monotonic()
        while True:
            for stream in (self.process.stdout, self.process.stderr):
                if stream is None:
                    continue
                rlist, _, _ = select.select([stream], [], [], 0.1)
                if rlist:
                    line = stream.readline()
                    if line:
                        match = regex.search(line)
                        if match and not url_printed:
                            url_printed = True
                            dev_url = match.group(1)
                            logger.info(f"DevTunnel URL: {dev_url}")
                            return dev_url
            if time.monotonic() - start > 15:
                raise Exception("Timeout: Failed to get devtunnel URL")

    def stop(self):
        super().stop()
        logger.info(f"Stopped {self.name} tunnel.")

class Btunnel(BaseTunnel):
    name = "Btunnel"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["./btunnel", "http", "--port", str(port), "-k", "JDJhJDEyJEYwLnRIUEVRMHEvbGlvczNmMTFSVnVaTEtoOGFObmhScHZNSHN6U3VYTHFGdmxyMWdteUUu"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, shell=True
        )
        try:
            match = wait_for_pattern(self.process, r"(https://[^\s]+-free\.in\.btunnel\.co\.in)", 10)
            url = match.group(1).strip()
            logger.info(f"Btunnel URL: {url}")
            return url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Btunnel") from e

class BeeceptorTunnel(BaseTunnel):
    name = "Beeceptor"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        self.process = subprocess.Popen(
            ["beeceptor-cli", "-p", str(port)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        if self.process.stdin:
            self.process.stdin.write("\n")
            self.process.stdin.flush()
        try:
            match = wait_for_pattern(self.process, r"(https://\S+\.free\.beeceptor\.com)", 10)
            url = match.group(1).strip()
            logger.info(f"Beeceptor URL: {url}")
            return url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Beeceptor Tunnel") from e

class OpenportTunnel(BaseTunnel):
    name = "Openport"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        logger.info("Starting Openport tunnel...")
        self.process = subprocess.Popen(
            ["openport", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        main_port = None
        start_time = time.monotonic()
        timeout = 45
        while time.monotonic() - start_time < timeout:
            for stream in (self.process.stdout, self.process.stderr):
                if stream is None:
                    continue
                rlist, _, _ = select.select([stream], [], [], 0.1)
                if rlist:
                    line = stream.readline()
                    if line:
                        port_match = re.search(r"forwarding remote port (spr\.openport\.io:\d+)", line)
                        if port_match and not main_port:
                            main_port = port_match.group(1)
                            logger.info(f"✓ Port allocated: {main_port}")
                        auth_match = re.search(r"first visit (https://spr\.openport\.io/l/\d+/\w+)", line)
                        if auth_match and main_port:
                            auth_url = auth_match.group(1)
                            logger.info(f"✓ Auth URL found: {auth_url}")
                            try:
                                response = requests.get(auth_url)
                                if response.status_code == 200:
                                    final_url = f"http://{main_port}"
                                    logger.info("✓ Authentication successful!")
                                    logger.info(f"✓ Final URL: {final_url}")
                                    return final_url
                            except Exception as err:
                                raise Exception(f"Failed to authenticate: {err}") from err
        raise Exception("Timeout: Failed to start Openport Tunnel")

    def stop(self):
        if self.process:
            logger.info("Stopping Openport tunnel...")
            self.process.kill()
            logger.info(f"✓ Stopped {self.name} tunnel")

class NgtorTunnel(BaseTunnel):
    name = "Ngtor"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        ensure_tor_running()
        self.process = subprocess.Popen(
            ["java", "-jar", "ngtor-0.1.0-boot.jar", "http", f"--port={port}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, r"(http://\S+\.onion)", 30)
            onion_url = match.group(1)
            logger.info(f"Ngtor Onion URL: {onion_url}")
            return onion_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Ngtor Tunnel") from e

class EphemeralHiddenServiceTunnel(BaseTunnel):
    name = "EphemeralHiddenService"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        ensure_tor_running()
        self.process = subprocess.Popen(
            ["ephemeral-hidden-service", "-lp", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        try:
            match = wait_for_pattern(self.process, r"(http://\S+\.onion)", 30)
            onion_url = match.group(1)
            logger.info(f"Ephemeral Hidden Service URL: {onion_url}")
            return onion_url
        except TimeoutError as e:
            raise Exception("Timeout: Failed to start Ephemeral Hidden Service") from e

class OnionpipeTunnel(BaseTunnel):
    name = "Onionpipe"

    def launch_tunnel(self, options) -> str:
        port = options.get("port", 3000)
        ensure_tor_running()
        self.process = subprocess.Popen(
            ["onionpipe", str(port)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        start = time.monotonic()
        while True:
            for stream in (self.process.stdout, self.process.stderr):
                if stream is None:
                    continue
                rlist, _, _ = select.select([stream], [], [], 0.1)
                if rlist:
                    line = stream.readline()
                    if line:
                        match = re.search(r"([a-z2-7]{16,56}\.onion):80", line)
                        if match:
                            onion_url = match.group(1)
                            logger.info(f"Onionpipe URL: {onion_url}")
                            return onion_url
            if time.monotonic() - start > 30:
                raise Exception("Timeout: Failed to start Onionpipe Tunnel")

    def stop(self):
        super().stop()

# ----------------- List of Tunnel Tools ----------------- #
tunnel_tools = [
    NgrokTunnel(),
    CloudflareTunnel(),
    DevTunnel(),
    ZrokTunnel(),
    LocalTunnel(),
    ServeoTunnel(),
    TelebitTunnel(),
    BoreTunnel(),
    LocalxposeTunnel(),
    ExposeTunnel(),
    LoopholeTunnel(),
    PinggyTunnel(),
    TailscaleTunnel(),
    OnionpipeTunnel(),
    NgtorTunnel(),
    OpenportTunnel(),
    TunwgTunnel(),
    PacketriotTunnel(),
    BoreDigitalTunnel(),
    LocalhostRunTunnel(),
    BeeceptorTunnel(),
    Btunnel(),
    TunnelPyjamas(),
    EphemeralHiddenServiceTunnel(),
    # PagekiteTunnel(),  # Uncomment if implemented.
]

# ----------------- CLI & Execution Functions ----------------- #
def print_header():
    header = textwrap.dedent("""\
    ===========================================
         Tunnel Tools Tester - CLI Utility
    ===========================================
    """)
    print(header)

def list_tools():
    print("Available Tunnel Tools:")
    for idx, tool in enumerate(tunnel_tools, start=1):
        print(f"  {idx}. {tool.name}")
    print()

def execute_tool(tool, options=None) -> bool:
    try:
        logger.info(f"Testing {tool.name} ...")
        url = tool.start(options)
        logger.info(f"✓ {tool.name} - URL: {url}")
        tool.stop()
        return True
    except Exception as e:
        logger.error(f"✗ {tool.name} - Error: {e}")
        return False

def run_all_tools(options=None):
    success_count = 0
    fail_count = 0
    for tool in tunnel_tools:
        if execute_tool(tool, options):
            success_count += 1
        else:
            fail_count += 1
    print("\nResults:")
    print(f"  ✓ Successful: {success_count}")
    print(f"  ✗ Failed: {fail_count}")
    print(f"  Total tools: {len(tunnel_tools)}")

def main():
    print_header()
    parser = argparse.ArgumentParser(
        description="Test tunnel tools by launching and stopping each tunnel."
    )
    parser.add_argument(
        "-t", "--tool", type=str, help="Tool number or name to test (e.g., '1' or 'LocalTunnel')"
    )
    parser.add_argument(
        "--all", action="store_true", help="Test all available tools."
    )
    parser.add_argument(
        "--port", type=int, default=3000, help="Port to use for testing tunnels."
    )
    args = parser.parse_args()

    options = {"port": args.port, "url_pattern": r"https://[^\s]+"}

    try:
        if args.all:
            logger.info("Running all tunnel tool tests...")
            run_all_tools(options)
        elif args.tool:
            list_tools()
            tool = None
            if args.tool.isdigit():
                index = int(args.tool) - 1
                if 0 <= index < len(tunnel_tools):
                    tool = tunnel_tools[index]
            else:
                for t in tunnel_tools:
                    if t.name.lower() == args.tool.lower():
                        tool = t
                        break
            if tool:
                logger.info(f"Testing tool: {tool.name}")
                if execute_tool(tool, options):
                    logger.info("Test completed successfully.")
                else:
                    logger.error("Test failed.")
            else:
                logger.error("Invalid tool selection. Please check the available tools below:")
                list_tools()
        else:
            list_tools()
            selection = input('Enter the number or name of the tool to test (or "all" to test all): ').strip()
            if selection.lower() == "all":
                run_all_tools(options)
            else:
                tool = None
                if selection.isdigit():
                    index = int(selection) - 1
                    if 0 <= index < len(tunnel_tools):
                        tool = tunnel_tools[index]
                else:
                    for t in tunnel_tools:
                        if t.name.lower() == selection.lower():
                            tool = t
                            break
                if tool:
                    logger.info(f"Testing tool: {tool.name}")
                    if execute_tool(tool, options):
                        logger.info("Test completed successfully.")
                    else:
                        logger.error("Test failed.")
                else:
                    logger.error("Invalid selection. Exiting.")
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received. Exiting.")
    except Exception as ex:
        logger.error(f"Error: {ex}")

if __name__ == '__main__':
    main()

# ----------------- End of tools.py ----------------- #