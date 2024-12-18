import threading
import statistics
import logging
import re
import psutil
import socket
import subprocess
from collections import deque
from time import monotonic, sleep
from typing import Dict, Any, Optional, Deque, Union

logger = logging.getLogger(__name__)

class NetworkMetricsCalculator:
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.metrics_lock = threading.Lock()
        self.start_time = monotonic()
        
        # Packet metrics with timestamps
        self.packet_timestamps = deque(maxlen=window_size)
        self.packet_sizes = deque(maxlen=window_size)
        self.total_packets = 0
        self.total_bytes = 0
        
        # Frame metrics
        self.frame_intervals = deque(maxlen=30)
        self.frame_sizes = deque(maxlen=30)
        self.total_frames = 0
        self.total_frames_lost = 0
        self.last_frame_time = None
        self.last_frame_number = 0
        self.frame_timestamps = deque(maxlen=30)
        
        # Interface monitoring
        self._interfaces = {}
        self._prev_stats = {}
        self._last_update = monotonic()
        self._update_interfaces()
        
        # Start monitoring thread
        self._monitor_thread = threading.Thread(target=self._monitor_network, daemon=True)
        self._monitor_thread.start()

    def _update_interfaces(self):
        """Update list of monitored interfaces"""
        try:
            interfaces = {}
            for iface in psutil.net_if_stats().keys():
                if iface.startswith('uesimtun') or iface == 'ogstun':
                    addr = self._get_interface_address(iface)
                    if addr:
                        interfaces[iface] = {
                            'address': addr,
                            'stats': psutil.net_io_counters(pernic=True).get(iface)
                        }
            self._interfaces = interfaces
        except Exception as e:
            logger.error(f"Error updating interfaces: {e}")

    def _get_interface_address(self, iface: str) -> Optional[str]:
        try:
            addrs = psutil.net_if_addrs().get(iface, [])
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    return addr.address
        except Exception as e:
            logger.error(f"Error getting interface address: {e}")
        return None

    def _calculate_jitter(self, timestamps: deque) -> float:
        if len(timestamps) < 2:
            return 0.0
            
        jitter = 0.0
        prev_timestamp = timestamps[0]
        
        for timestamp in list(timestamps)[1:]:
            delay = abs(timestamp - prev_timestamp)
            jitter = jitter + (delay - jitter) / 16
            prev_timestamp = timestamp
            
        return jitter * 1000

    def record_data_sent(self, data: Any, timestamp: float) -> None:
        """Record metrics for sent data"""
        with self.metrics_lock:
            size = len(data) if isinstance(data, (bytes, str)) else len(str(data))
            self.total_bytes += size
            self.total_packets += 1
            self.packet_sizes.append(size)
            self.packet_timestamps.append(timestamp)
            
            if isinstance(data, bytes):  # Frame data
                self.total_frames += 1
                self.frame_sizes.append(size)
                self.frame_timestamps.append(timestamp)
                
                if self.last_frame_time is not None:
                    interval = timestamp - self.last_frame_time
                    if interval > 0:  # Avoid division by zero
                        self.frame_intervals.append(interval)
                        
                    # Check for lost frames based on frame timing
                    expected_interval = 1/30.0  # Assuming 30 FPS target
                    if interval > expected_interval * 2:  # If interval is more than double expected
                        estimated_lost_frames = int(interval/expected_interval) - 1
                        self.total_frames_lost += estimated_lost_frames
                
                self.last_frame_time = timestamp
                self.last_frame_number += 1

    def record_data_received(self, data: Any, timestamp: float, content_type: str) -> None:
        """Record metrics for received data"""
        with self.metrics_lock:
            size = len(data) if isinstance(data, (bytes, str)) else len(str(data))
            self.total_bytes += size
            self.total_packets += 1
            self.packet_sizes.append(size)
            self.packet_timestamps.append(timestamp)
            
            if 'image' in content_type:  # Frame data
                self.total_frames += 1
                self.frame_sizes.append(size)
                self.frame_timestamps.append(timestamp)
                
                if self.last_frame_time is not None:
                    interval = timestamp - self.last_frame_time
                    if interval > 0:
                        self.frame_intervals.append(interval)
                        
                    # Check for lost frames
                    expected_interval = 1/30.0  # Assuming 30 FPS target
                    if interval > expected_interval * 2:
                        estimated_lost_frames = int(interval/expected_interval) - 1
                        self.total_frames_lost += estimated_lost_frames
                
                self.last_frame_time = timestamp
                self.last_frame_number += 1

    def calculate_metrics(self) -> Dict[str, Any]:
        """Calculate all network metrics"""
        with self.metrics_lock:
            current_time = monotonic()
            elapsed = current_time - self.start_time
            
            # Calculate base metrics
            metrics = {
                "throughput": {
                    "total_mbps": (self.total_bytes * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0
                },
                "latency": {
                    "min_ms": 0,
                    "max_ms": 0,
                    "avg_ms": 0,
                    "jitter_ms": self._calculate_jitter(self.packet_timestamps)
                }
            }
            
            # Get interface-specific metrics
            self._update_interfaces()
            for iface, data in self._interfaces.items():
                if iface.startswith('uesimtun'):
                    latency = self._measure_interface_latency(iface)
                    if latency > 0:
                        metrics['latency'].update({
                            "min_ms": min(metrics['latency']['min_ms'], latency) if metrics['latency']['min_ms'] > 0 else latency,
                            "max_ms": max(metrics['latency']['max_ms'], latency),
                            "avg_ms": latency if metrics['latency']['avg_ms'] == 0 else (metrics['latency']['avg_ms'] + latency) / 2
                        })
            
            # Calculate frame metrics
            current_fps = 0
            frame_loss_percent = 0
            
            if self.frame_intervals:
                current_fps = 1 / statistics.mean(self.frame_intervals) if self.frame_intervals else 0
                
                if self.total_frames > 0:
                    frame_loss_percent = (self.total_frames_lost / (self.total_frames + self.total_frames_lost)) * 100
            
            # Add frame metrics
            metrics["frame_metrics"] = {
                "frame_rate": {
                    "current_fps": current_fps,
                    "frame_time_ms": statistics.mean(self.frame_intervals) * 1000 if self.frame_intervals else 0,
                    "total_frames": self.total_frames,  # Added this line
                    "frames_received": self.total_frames  # Added this line
                },
                "frame_size": {
                    "avg_bytes": statistics.mean(self.frame_sizes) if self.frame_sizes else 0,
                    "max_bytes": max(self.frame_sizes) if self.frame_sizes else 0,
                    "min_bytes": min(self.frame_sizes) if self.frame_sizes else 0
                },
                "total_frames": self.total_frames,
                "frames_lost": self.total_frames_lost,
                "frame_loss_percent": frame_loss_percent
            }
            
            # Additional frame stats directly in metrics root
            metrics["frames"] = {              # Added this section
                "total": self.total_frames,
                "received": self.total_frames,
                "lost": self.total_frames_lost,
                "loss_percent": frame_loss_percent
            }
            
            return metrics

    def _measure_interface_latency(self, interface: str) -> float:
        try:
            result = subprocess.run(
                ['ping', '-I', interface, '-c', '1', '-W', '1', '10.45.0.1'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                match = re.search(r'time=([\d.]+)', result.stdout)
                if match:
                    return float(match.group(1))
            return 0
        except Exception as e:
            logger.error(f"Error measuring latency for interface {interface}: {e}")
            return 0

    def _monitor_network(self):
        while True:
            try:
                self._update_interfaces()
                sleep(1)
            except Exception as e:
                logger.error(f"Error in network monitor: {e}")
                sleep(5)

    def reset(self):
        """Reset all metrics"""
        with self.metrics_lock:
            self.start_time = monotonic()
            self.packet_timestamps.clear()
            self.packet_sizes.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self.frame_intervals.clear()
            self.frame_sizes.clear()
            self.frame_timestamps.clear()
            self.total_frames = 0
            self.total_frames_lost = 0
            self.last_frame_time = None
            self.last_frame_number = 0
            self._prev_stats = {}