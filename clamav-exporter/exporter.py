#!/usr/bin/env python3
"""
ClamAV Prometheus Exporter
Exports ClamAV statistics and database information to Prometheus
"""

import socket
import time
import re
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Try multiple possible socket paths
CLAMAV_SOCKET_PATHS = [
    '/var/run/clamav/clamd.ctl',
    '/var/run/clamav/clamd.sock',
    '/var/run/clamav/clamd.socket',
    '/tmp/clamd.socket'
]
# TCP connection as fallback
CLAMAV_TCP_HOST = 'clamav'
CLAMAV_TCP_PORT = 3310
EXPORTER_PORT = 9810

class ClamAVMetrics:
    def __init__(self):
        self.stats = {}
        self.version_info = {}
        self.socket_path = None
        self.use_tcp = False
        self.find_socket()

    def find_socket(self):
        """Find the ClamAV socket path or use TCP"""
        # First, list what's actually in the socket directory
        socket_dirs = ['/var/run/clamav', '/var/run', '/tmp']
        for socket_dir in socket_dirs:
            if os.path.exists(socket_dir):
                try:
                    files = os.listdir(socket_dir)
                    logger.info(f"Files in {socket_dir}: {files}")
                except Exception as e:
                    logger.debug(f"Cannot list {socket_dir}: {e}")

        # Try to find Unix socket
        for socket_path in CLAMAV_SOCKET_PATHS:
            if os.path.exists(socket_path):
                self.socket_path = socket_path
                self.use_tcp = False
                logger.info(f"Found ClamAV Unix socket at: {socket_path}")
                return

        # If no Unix socket found, try TCP
        logger.warning(f"No Unix socket found. Tried: {CLAMAV_SOCKET_PATHS}")
        logger.info(f"Attempting to use TCP connection to {CLAMAV_TCP_HOST}:{CLAMAV_TCP_PORT}")
        self.use_tcp = True

    def connect_and_send(self, command):
        """Connect to ClamAV via socket or TCP and send command"""
        try:
            if self.use_tcp:
                # Use TCP connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((CLAMAV_TCP_HOST, CLAMAV_TCP_PORT))
                logger.debug(f"Connected via TCP to {CLAMAV_TCP_HOST}:{CLAMAV_TCP_PORT}")
            else:
                # Use Unix socket
                if not self.socket_path:
                    self.find_socket()
                    if not self.socket_path and not self.use_tcp:
                        logger.error("No ClamAV connection available")
                        return None

                if self.use_tcp:
                    # find_socket may have switched to TCP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((CLAMAV_TCP_HOST, CLAMAV_TCP_PORT))
                else:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect(self.socket_path)
                    logger.debug(f"Connected via Unix socket at {self.socket_path}")

            # Send command with proper protocol (use 'z' for null-terminated)
            sock.sendall(f'z{command}\0'.encode())

            # Receive response
            response = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break

            sock.close()
            return response.decode('utf-8', errors='ignore')

        except Exception as e:
            if self.use_tcp:
                logger.error(f"Error connecting to ClamAV via TCP {CLAMAV_TCP_HOST}:{CLAMAV_TCP_PORT}: {e}")
            else:
                logger.error(f"Error connecting to ClamAV socket {self.socket_path}: {e}")
            return None

    def get_stats(self):
        """Get ClamAV statistics"""
        response = self.connect_and_send('STATS')
        if not response:
            logger.warning("No STATS response from ClamAV")
            return {}

        logger.debug(f"STATS response: {response[:200]}")  # Log first 200 chars
        stats = {}

        # Parse STATS output
        for line in response.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()

                # Extract numeric values
                if key == 'POOLS':
                    match = re.search(r'(\d+)', value)
                    if match:
                        stats['pools'] = int(match.group(1))
                elif key == 'STATE':
                    if 'VALID PRIMARY' in value:
                        stats['state'] = 1
                    else:
                        stats['state'] = 0
                elif key == 'THREADS':
                    match = re.search(r'live (\d+)', value)
                    if match:
                        stats['threads_live'] = int(match.group(1))
                    match = re.search(r'idle (\d+)', value)
                    if match:
                        stats['threads_idle'] = int(match.group(1))
                elif key == 'QUEUE':
                    match = re.search(r'(\d+) items', value)
                    if match:
                        stats['queue_items'] = int(match.group(1))
                elif key == 'MEMSTATS':
                    match = re.search(r'heap ([\d.]+)M mmap ([\d.]+)M used ([\d.]+)M free ([\d.]+)M', value)
                    if match:
                        stats['memory_heap_mb'] = float(match.group(1))
                        stats['memory_mmap_mb'] = float(match.group(2))
                        stats['memory_used_mb'] = float(match.group(3))
                        stats['memory_free_mb'] = float(match.group(4))

        if stats:
            logger.info(f"Parsed {len(stats)} stats from STATS command")
        return stats

    def get_version(self):
        """Get ClamAV version information"""
        response = self.connect_and_send('VERSION')
        if not response:
            logger.warning("No VERSION response from ClamAV")
            return {}

        logger.debug(f"VERSION response: {response}")
        version_info = {}

        # Example: ClamAV 1.0.0/26853/Thu Mar 16 08:15:13 2023
        match = re.search(r'ClamAV ([0-9.]+)/(\d+)', response)
        if match:
            version_info['version'] = match.group(1)
            version_info['signature_version'] = int(match.group(2))
            logger.info(f"ClamAV version: {version_info['version']}, signatures: {version_info['signature_version']}")

        return version_info

    def parse_logs(self):
        """Parse ClamAV logs for virus detections and scan statistics"""
        stats = {
            'viruses_found_total': 0,
            'files_scanned_total': 0,
            'database_updated': 0
        }

        # Try to read clamd.log
        for log_path in ['/var/log/clamav/clamd.log', '/var/log/clamd.log']:
            try:
                if os.path.exists(log_path):
                    with open(log_path, 'r') as f:
                        lines = f.readlines()
                        logger.info(f"Reading {len(lines)} lines from {log_path}")

                        for line in lines:
                            # Count virus detections (lines with FOUND)
                            if 'FOUND' in line and not line.strip().startswith('#'):
                                stats['viruses_found_total'] += 1

                            # Count individual file scans
                            # ClamAV logs format: "/path/to/file: OK" or "/path/to/file: Win.Virus FOUND"
                            # Also counts stream scans: "stream: OK" or "stream: Win.Virus FOUND"
                            if ': OK' in line or ': FOUND' in line:
                                # This is a scan result line
                                if not line.strip().startswith('#') and ('/' in line or 'stream:' in line):
                                    stats['files_scanned_total'] += 1

                            # Parse scan summary (if available)
                            match = re.search(r'Scanned files: (\d+)', line)
                            if match:
                                # Use the summary count if available (more accurate)
                                summary_count = int(match.group(1))
                                if summary_count > stats['files_scanned_total']:
                                    stats['files_scanned_total'] = summary_count
                    break
            except Exception as e:
                logger.debug(f"Could not parse {log_path}: {e}")

        # Try to read freshclam.log for update info
        for log_path in ['/var/log/clamav/freshclam.log', '/var/log/freshclam.log']:
            try:
                if os.path.exists(log_path):
                    with open(log_path, 'r') as f:
                        lines = f.readlines()
                        logger.info(f"Reading {len(lines)} lines from {log_path}")

                        for line in reversed(lines):  # Start from most recent
                            # Check for successful update
                            if 'Database updated' in line or 'is up-to-date' in line or 'bytecode database available' in line:
                                stats['database_updated'] = 1
                                logger.info("Database is updated")
                                break
                    break
            except Exception as e:
                logger.debug(f"Could not parse {log_path}: {e}")

        logger.info(f"Parsed logs - viruses: {stats['viruses_found_total']}, scanned: {stats['files_scanned_total']}, db_updated: {stats['database_updated']}")
        return stats

    def update_metrics(self):
        """Update all metrics"""
        self.stats = self.get_stats()
        self.version_info = self.get_version()
        log_stats = self.parse_logs()
        self.stats.update(log_stats)

    def format_prometheus(self):
        """Format metrics in Prometheus format"""
        lines = []

        # Help and type definitions
        lines.append('# HELP clamav_up ClamAV daemon is up and responding')
        lines.append('# TYPE clamav_up gauge')
        lines.append(f'clamav_up {1 if self.stats else 0}')

        if self.stats.get('state') is not None:
            lines.append('# HELP clamav_state ClamAV daemon state (1=valid, 0=invalid)')
            lines.append('# TYPE clamav_state gauge')
            lines.append(f'clamav_state {self.stats["state"]}')

        if self.stats.get('pools') is not None:
            lines.append('# HELP clamav_pools_total Total number of pools')
            lines.append('# TYPE clamav_pools_total gauge')
            lines.append(f'clamav_pools_total {self.stats["pools"]}')

        if self.stats.get('threads_live') is not None:
            lines.append('# HELP clamav_threads_live Number of live threads')
            lines.append('# TYPE clamav_threads_live gauge')
            lines.append(f'clamav_threads_live {self.stats["threads_live"]}')

        if self.stats.get('threads_idle') is not None:
            lines.append('# HELP clamav_threads_idle Number of idle threads')
            lines.append('# TYPE clamav_threads_idle gauge')
            lines.append(f'clamav_threads_idle {self.stats["threads_idle"]}')

        if self.stats.get('queue_items') is not None:
            lines.append('# HELP clamav_queue_items Number of items in queue')
            lines.append('# TYPE clamav_queue_items gauge')
            lines.append(f'clamav_queue_items {self.stats["queue_items"]}')

        if self.stats.get('memory_heap_mb') is not None:
            lines.append('# HELP clamav_memory_heap_mb Heap memory in MB')
            lines.append('# TYPE clamav_memory_heap_mb gauge')
            lines.append(f'clamav_memory_heap_mb {self.stats["memory_heap_mb"]}')

        if self.stats.get('memory_used_mb') is not None:
            lines.append('# HELP clamav_memory_used_mb Used memory in MB')
            lines.append('# TYPE clamav_memory_used_mb gauge')
            lines.append(f'clamav_memory_used_mb {self.stats["memory_used_mb"]}')

        if self.version_info.get('signature_version') is not None:
            lines.append('# HELP clamav_signature_version Current virus signature database version')
            lines.append('# TYPE clamav_signature_version gauge')
            lines.append(f'clamav_signature_version {self.version_info["signature_version"]}')

        if self.version_info.get('version'):
            lines.append(f'# HELP clamav_version ClamAV version info')
            lines.append(f'# TYPE clamav_version gauge')
            lines.append(f'clamav_version{{version="{self.version_info["version"]}"}} 1')

        if self.stats.get('viruses_found_total') is not None:
            lines.append('# HELP clamav_viruses_found_total Total number of viruses found')
            lines.append('# TYPE clamav_viruses_found_total counter')
            lines.append(f'clamav_viruses_found_total {self.stats["viruses_found_total"]}')

        if self.stats.get('files_scanned_total') is not None:
            lines.append('# HELP clamav_files_scanned_total Total number of files scanned')
            lines.append('# TYPE clamav_files_scanned_total counter')
            lines.append(f'clamav_files_scanned_total {self.stats["files_scanned_total"]}')

        if self.stats.get('database_updated') is not None:
            lines.append('# HELP clamav_database_updated Database update status (1=updated, 0=not updated)')
            lines.append('# TYPE clamav_database_updated gauge')
            lines.append(f'clamav_database_updated {self.stats["database_updated"]}')

        return '\n'.join(lines) + '\n'

# Global metrics object
metrics = ClamAVMetrics()

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            try:
                metrics.update_metrics()
                output = metrics.format_prometheus()

                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; version=0.0.4')
                self.end_headers()
                self.wfile.write(output.encode())
            except Exception as e:
                logger.error(f"Error generating metrics: {e}")
                self.send_response(500)
                self.end_headers()
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default logging
        pass

def run_server():
    server = HTTPServer(('0.0.0.0', EXPORTER_PORT), MetricsHandler)
    logger.info(f'Starting ClamAV exporter on port {EXPORTER_PORT}')
    server.serve_forever()

if __name__ == '__main__':
    # Wait for ClamAV to be ready
    logger.info('Waiting for ClamAV to be ready...')
    time.sleep(10)

    run_server()
