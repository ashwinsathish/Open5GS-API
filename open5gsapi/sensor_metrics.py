import threading
import statistics
import logging
import json
from collections import deque
from time import monotonic
from typing import Dict, Any

logger = logging.getLogger(__name__)

class SensorMetricsCalculator:
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.metrics_lock = threading.Lock()
        
        # Store timestamps and sizes
        self.packet_sizes = deque(maxlen=window_size)  
        self.latencies = deque(maxlen=window_size)
        self.throughputs = deque(maxlen=window_size)
        
        # For RFC 3550 jitter calculation
        self.last_transit = None
        self.jitter = 0
        self.jitters = deque(maxlen=window_size)  # Store jitter values
        
        logger.info("SensorMetricsCalculator initialized")

    def record_data_sent(self, data: Any, timestamp: float) -> None:
        """Record sent data with timestamp"""
        with self.metrics_lock:
            try:
                size = len(json.dumps(data).encode('utf-8'))
                self.packet_sizes.append(size)
                
                logger.debug(f"Recorded sent data size: {size} bytes at {timestamp}")
                
            except Exception as e:
                logger.error(f"Error in record_data_sent: {e}")

    def record_data_received(self, data: Any, timestamp: float, content_type: str) -> None:
        """Record received data and calculate metrics"""
        with self.metrics_lock:
            try:
                if isinstance(data, dict) and 'sensor_id' in data and '_send_timestamp' in data:
                    send_time = float(data['_send_timestamp'])
                    size = len(json.dumps(data).encode('utf-8'))
                    self.packet_sizes.append(size)
                    
                    # Calculate latency (in milliseconds)
                    latency = (timestamp - send_time) * 1000
                    
                    # Only process valid latencies
                    if 0 < latency < 1000:  # Sanity check: latency between 0 and 1000ms
                        self.latencies.append(latency)
                        
                        # Calculate throughput (bits per second)
                        throughput = (size * 8) / (latency / 1000)
                        self.throughputs.append(throughput)
                        
                        # Calculate RFC 3550 jitter
                        if self.last_transit is not None:
                            # Transit time difference
                            d = abs(latency - self.last_transit)
                            # RFC 3550 jitter calculation
                            self.jitter = self.jitter + (d - self.jitter) / 16
                            self.jitters.append(self.jitter)
                            
                        self.last_transit = latency
                        
                        logger.debug(f"""Metrics recorded:
                            Sensor: {data['sensor_id']}
                            Latency: {latency:.2f} ms
                            Throughput: {throughput:.2f} bps
                            Size: {size} bytes
                            Jitter: {self.jitter:.2f} ms""")
                    
            except Exception as e:
                logger.error(f"Error in record_data_received: {e}")

    def calculate_metrics(self) -> Dict[str, Any]:
        """Calculate current metrics"""
        with self.metrics_lock:
            try:
                # Only use valid latencies (0-1000ms range)
                valid_latencies = [l for l in self.latencies if 0 < l < 1000]
                
                metrics = {
                    "latency": {
                        "current_ms": valid_latencies[-1] if valid_latencies else 0,
                        "avg_ms": statistics.mean(valid_latencies) if valid_latencies else 0,
                        "min_ms": min(valid_latencies) if valid_latencies else 0,
                        "max_ms": max(valid_latencies) if valid_latencies else 0
                    },
                    "throughput": {
                        "current_bps": self.throughputs[-1] if self.throughputs else 0,
                        "avg_bps": statistics.mean(self.throughputs) if self.throughputs else 0,
                        "min_bps": min(self.throughputs) if self.throughputs else 0,
                        "max_bps": max(self.throughputs) if self.throughputs else 0
                    },
                    "jitter": {
                        "current_ms": self.jitters[-1] if self.jitters else 0,
                        "avg_ms": statistics.mean(self.jitters) if self.jitters else 0,
                        "min_ms": min(self.jitters) if self.jitters else 0,
                        "max_ms": max(self.jitters) if self.jitters else 0
                    },
                    "packet_size": {
                        "current_bytes": self.packet_sizes[-1] if self.packet_sizes else 0,
                        "avg_bytes": statistics.mean(self.packet_sizes) if self.packet_sizes else 0,
                        "min_bytes": min(self.packet_sizes) if self.packet_sizes else 0,
                        "max_bytes": max(self.packet_sizes) if self.packet_sizes else 0
                    }
                }
                
                logger.debug(f"Calculated metrics: {metrics}")
                return metrics
                
            except Exception as e:
                logger.error(f"Error calculating metrics: {e}")
                return {
                    "latency": {"current_ms": 0, "avg_ms": 0, "min_ms": 0, "max_ms": 0},
                    "throughput": {"current_bps": 0, "avg_bps": 0, "min_bps": 0, "max_bps": 0},
                    "jitter": {"current_ms": 0, "avg_ms": 0, "min_ms": 0, "max_ms": 0},
                    "packet_size": {"current_bytes": 0, "avg_bytes": 0, "min_bytes": 0, "max_bytes": 0}
                }

    def reset(self):
        with self.metrics_lock:
            self.latencies.clear()
            self.throughputs.clear()
            self.jitters.clear()
            self.packet_sizes.clear()
            self.last_latency = None
            self.start_time = monotonic()