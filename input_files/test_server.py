import requests
import json
import time

SERVER_URL = "http://localhost:3000"

def test_health():
    print("=== Testing /health endpoint ===")
    resp = requests.get(f"{SERVER_URL}/health")
    print("Status Code:", resp.status_code)
    print("Response:", resp.json())
    assert resp.status_code == 200, "Health endpoint failed"

def test_diagnostics():
    print("\n=== Testing /diagnostics endpoint ===")
    resp = requests.get(f"{SERVER_URL}/diagnostics")
    print("Status Code:", resp.status_code)
    print("Response:", json.dumps(resp.json(), indent=2))
    assert resp.status_code == 200, "Diagnostics endpoint failed"

def test_upload_test():
    print("\n=== Testing /upload-test endpoint ===")
    file_content = b"This is a test file for upload."
    files = {"file": ("test.txt", file_content)}
    resp = requests.post(f"{SERVER_URL}/upload-test", files=files)
    print("Status Code:", resp.status_code)
    print("Response:", resp.json())
    assert resp.status_code == 200, "Upload test failed"

def test_webtest():
    print("\n=== Testing /webtest endpoint ===")
    resp = requests.get(f"{SERVER_URL}/webtest")
    content_type = resp.headers.get("content-type", "")
    print("Status Code:", resp.status_code)
    print("Content-Type:", content_type)
    assert "text/html" in content_type, "Webtest endpoint failed"

def test_files():
    print("\n=== Testing /files endpoint ===")
    resp = requests.get(f"{SERVER_URL}/files")
    print("Status Code:", resp.status_code)
    try:
        files_metadata = resp.json()
        print("Files Metadata:", json.dumps(files_metadata, indent=2))
    except Exception as e:
        print("Error parsing JSON response:", e)
    assert resp.status_code == 200, "Files endpoint failed"

def test_tunnel():
    print("\n=== Testing tunnel endpoints ===")
    payload = {"toolName": "Serveo"}
    print("Starting tunnel with tool 'Serveo'...")
    resp = requests.post(f"{SERVER_URL}/start-tunnel", json=payload)
    print("Status Code:", resp.status_code)
    # If starting the tunnel fails, assert with the error message
    assert resp.status_code == 200, f"Start tunnel failed: {resp.json()}"
    data = resp.json()
    tunnel_url = data.get("url")
    print("Tunnel started with URL:", tunnel_url)
    # Wait briefly before stopping to simulate usage
    time.sleep(5)
    print("Stopping tunnel...")
    resp_stop = requests.post(f"{SERVER_URL}/stop-tunnel")
    print("Stop Tunnel Response:", resp_stop.json())
    assert resp_stop.status_code == 200, "Stop tunnel failed"

def main():
    try:
        test_health()
        test_diagnostics()
        test_upload_test()
        test_webtest()
        test_files()
        test_tunnel()
        print("\nAll tests completed successfully.")
    except AssertionError as ae:
        print("\nTest assertion failed:", ae)
    except Exception as e:
        print("\nAn unexpected error occurred:", e)

if __name__ == '__main__':
    main()
