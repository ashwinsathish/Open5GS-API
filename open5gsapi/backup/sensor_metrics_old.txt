# import threading
# import statistics
# import logging
# import re
# import psutil
# import socket
# import subprocess
# from collections import deque
# from time import monotonic, sleep
# from typing import Dict, Any, Optional, Deque, Union
# import json

# logger = logging.getLogger(__name__)

# class SensorMetricsCalculator:
#     def __init__(self, window_size: int = 100):
#         self.window_size = window_size
#         self.metrics_lock = threading.Lock()
#         self.start_time = monotonic()
        
#         # Packet metrics with timestamps
#         self.packet_timestamps = deque(maxlen=window_size)
#         self.packet_sizes = deque(maxlen=window_size)
#         self.total_packets = 0
#         self.total_bytes = 0
        
#         # Sensor specific metrics
#         self.sensor_readings = deque(maxlen=window_size)
#         self.sensor_intervals = deque(maxlen=30)
#         self.total_readings = 0
#         self.readings_lost = 0
#         self.last_reading_time = None
#         self.last_sequence_number = -1
#         self.readings_by_sensor = {}  # Track readings per sensor ID
#         self.sensor_timestamps = deque(maxlen=30)
        
#         # Interface monitoring
#         self._interfaces = {}
#         self._prev_stats = {}
#         self._last_update = monotonic()
#         self._update_interfaces()
        
#         # Start monitoring thread
#         self._monitor_thread = threading.Thread(target=self._monitor_network, daemon=True)
#         self._monitor_thread.start()

#     def _update_interfaces(self):
#         try:
#             interfaces = {}
#             for iface in psutil.net_if_stats().keys():
#                 if iface.startswith('uesimtun') or iface == 'ogstun':
#                     addr = self._get_interface_address(iface)
#                     if addr:
#                         interfaces[iface] = {
#                             'address': addr,
#                             'stats': psutil.net_io_counters(pernic=True).get(iface)
#                         }
#             self._interfaces = interfaces
#         except Exception as e:
#             logger.error(f"Error updating interfaces: {e}")

#     def _get_interface_address(self, iface: str) -> Optional[str]:
#         try:
#             addrs = psutil.net_if_addrs().get(iface, [])
#             for addr in addrs:
#                 if addr.family == socket.AF_INET:
#                     return addr.address
#         except Exception as e:
#             logger.error(f"Error getting interface address: {e}")
#         return None

#     # def _calculate_jitter(self, timestamps: deque) -> float:
#     #     if len(timestamps) < 2:
#     #         return 0.0
#     #     jitter = 0.0
#     #     prev_timestamp = timestamps[0]
#     #     for timestamp in list(timestamps)[1:]:
#     #         delay = abs(timestamp - prev_timestamp)
#     #         jitter = jitter + (delay - jitter) / 16
#     #         prev_timestamp = timestamp
#     #     return jitter * 1000

#     def _calculate_jitter(self, timestamps: deque) -> float:
#         """Calculate jitter using RFC 3550 algorithm"""
#         if len(timestamps) < 2:
#             return 0.0
            
#         delays = []
#         timestamps_list = sorted(list(timestamps))
#         for i in range(1, len(timestamps_list)):
#             delay = timestamps_list[i] - timestamps_list[i-1]
#             delays.append(delay)
        
#         if not delays:
#             return 0.0
            
#         avg_delay = sum(delays) / len(delays)
#         jitter = sum(abs(d - avg_delay) for d in delays) / len(delays)
#         return jitter * 1000  # Convert to ms

#     def record_data_sent(self, data: Any, timestamp: float) -> None:
#         with self.metrics_lock:
#             size = len(str(data)) if isinstance(data, (dict, list)) else len(data)
#             self.total_bytes += size
#             self.total_packets += 1
#             self.packet_sizes.append(size)
#             self.packet_timestamps.append(timestamp)
            
#             if isinstance(data, dict) and "sensor_id" in data:
#                 self.total_readings += 1
#                 sensor_id = data["sensor_id"]
                
#                 if sensor_id not in self.readings_by_sensor:
#                     self.readings_by_sensor[sensor_id] = {
#                         "total_readings": 0,
#                         "last_sequence": -1,
#                         "readings_lost": 0,
#                         "values": deque(maxlen=30)
#                     }
                
#                 self.readings_by_sensor[sensor_id]["total_readings"] += 1
#                 self.readings_by_sensor[sensor_id]["values"].append({
#                     "timestamp": timestamp,
#                     "value": data
#                 })
                
#                 if self.last_reading_time is not None:
#                     interval = timestamp - self.last_reading_time
#                     if interval > 0:
#                         self.sensor_intervals.append(interval)
                
#                 self.last_reading_time = timestamp
#                 self.sensor_timestamps.append(timestamp)

#     def record_data_received(self, data: Any, timestamp: float, content_type: str) -> None:
#         with self.metrics_lock:
#             size = len(str(data)) if isinstance(data, (dict, list)) else len(data)
#             self.total_bytes += size
#             self.total_packets += 1
#             self.packet_sizes.append(size)
#             self.packet_timestamps.append(timestamp)
            
#             if isinstance(data, dict) and "sensor_id" in data and "sequence" in data:
#                 try:
#                     sensor_id = data["sensor_id"]
#                     current_sequence = data["sequence"]
                    
#                     if sensor_id not in self.readings_by_sensor:
#                         self.readings_by_sensor[sensor_id] = {
#                             "total_readings": 0,
#                             "last_sequence": -1,
#                             "readings_lost": 0,
#                             "values": deque(maxlen=30)
#                         }
                    
#                     sensor_info = self.readings_by_sensor[sensor_id]
#                     if sensor_info["last_sequence"] >= 0:
#                         expected_sequence = sensor_info["last_sequence"] + 1
#                         if current_sequence > expected_sequence:
#                             readings_lost = current_sequence - expected_sequence
#                             sensor_info["readings_lost"] += readings_lost
#                             self.readings_lost += readings_lost
                    
#                     sensor_info["last_sequence"] = current_sequence
#                     sensor_info["total_readings"] += 1
#                     sensor_info["values"].append({
#                         "timestamp": timestamp,
#                         "value": data
#                     })
                    
#                     self.total_readings += 1
#                     self.sensor_readings.append(data)
#                     self.sensor_timestamps.append(timestamp)
                    
#                     if self.last_reading_time is not None:
#                         interval = timestamp - self.last_reading_time
#                         if interval > 0:
#                             self.sensor_intervals.append(interval)
                    
#                     self.last_reading_time = timestamp
                    
#                 except Exception as e:
#                     logger.error(f"Error processing sensor reading: {e}")

#     # def calculate_metrics(self) -> Dict[str, Any]:
#     #     with self.metrics_lock:
#     #         current_time = monotonic()
#     #         elapsed = current_time - self.start_time
            
#     #         metrics = {
#     #             "throughput": {
#     #                 "total_mbps": (self.total_bytes * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0
#     #             },
#     #             "latency": {
#     #                 "min_ms": 0,
#     #                 "max_ms": 0,
#     #                 "avg_ms": 0,
#     #                 "jitter_ms": self._calculate_jitter(self.packet_timestamps)
#     #             }
#     #         }
            
#     #         # Interface latency measurement
#     #         self._update_interfaces()
#     #         for iface, data in self._interfaces.items():
#     #             if iface.startswith('uesimtun'):
#     #                 latency = self._measure_interface_latency(iface)
#     #                 if latency > 0:
#     #                     metrics['latency'].update({
#     #                         "min_ms": min(metrics['latency']['min_ms'], latency) if metrics['latency']['min_ms'] > 0 else latency,
#     #                         "max_ms": max(metrics['latency']['max_ms'], latency),
#     #                         "avg_ms": latency if metrics['latency']['avg_ms'] == 0 else (metrics['latency']['avg_ms'] + latency) / 2
#     #                     })
            
#     #         # Calculate readings per second
#     #         readings_per_second = 0
#     #         if self.sensor_intervals:
#     #             avg_interval = statistics.mean(self.sensor_intervals)
#     #             if avg_interval > 0:
#     #                 readings_per_second = 1 / avg_interval
            
#     #         # Sensor metrics
#     #         metrics["sensor_metrics"] = {
#     #             "reading_rate": {
#     #                 "current_rps": readings_per_second,
#     #                 "reading_interval_ms": statistics.mean(self.sensor_intervals) * 1000 if self.sensor_intervals else 0,
#     #                 "total_readings": self.total_readings,
#     #                 "readings_lost": self.readings_lost
#     #             },
#     #             "by_sensor": {}
#     #         }
            
#     #         # Per-sensor metrics
#     #         for sensor_id, sensor_data in self.readings_by_sensor.items():
#     #             latest_readings = list(sensor_data["values"])
#     #             if latest_readings:
#     #                 latest_values = [r["value"] for r in latest_readings]
#     #                 metrics["sensor_metrics"]["by_sensor"][sensor_id] = {
#     #                     "total_readings": sensor_data["total_readings"],
#     #                     "readings_lost": sensor_data["readings_lost"],
#     #                     "latest_value": latest_values[-1],
#     #                     "min_value": min(latest_values, key=lambda x: x.get("value", 0)),
#     #                     "max_value": max(latest_values, key=lambda x: x.get("value", 0)),
#     #                     "avg_value": statistics.mean([x.get("value", 0) for x in latest_values])
#     #                 }
            
#     #         return metrics

#     def calculate_metrics(self) -> Dict[str, Any]:
#         with self.metrics_lock:
#             current_time = monotonic()
#             elapsed = current_time - self.start_time
            
#             # Calculate throughput
#             total_bytes = self.total_bytes
#             throughput_mbps = (total_bytes * 8) / (1_000_000 * max(elapsed, 1))
            
#             # Calculate latency statistics
#             latencies = []
#             for sensor_data in self.readings_by_sensor.values():
#                 for reading in sensor_data['values']:
#                     if 'timestamp' in reading and 'value' in reading and 'timestamp' in reading['value']:
#                         receive_time = reading['timestamp']
#                         send_time = reading['value']['timestamp']
#                         latency = receive_time - send_time
#                         if latency >= 0:
#                             latencies.append(latency * 1000)
            
#             # Calculate jitter
#             jitter = 0
#             if len(self.packet_timestamps) >= 2:
#                 delays = []
#                 timestamps = sorted(list(self.packet_timestamps))
#                 for i in range(1, len(timestamps)):
#                     delay = timestamps[i] - timestamps[i-1]
#                     delays.append(delay)
                
#                 if delays:
#                     avg_delay = sum(delays) / len(delays)
#                     jitter = sum(abs(d - avg_delay) for d in delays) / len(delays)
#                     jitter *= 1000  # Convert to ms
            
#             # Calculate readings per second
#             current_rps = 0
#             if self.sensor_intervals:
#                 avg_interval = statistics.mean(self.sensor_intervals)
#                 if avg_interval > 0:
#                     current_rps = 1 / avg_interval
            
#             metrics = {
#                 "throughput": {
#                     "total_mbps": throughput_mbps
#                 },
#                 "latency": {
#                     "min_ms": min(latencies) if latencies else 0,
#                     "max_ms": max(latencies) if latencies else 0,
#                     "avg_ms": sum(latencies) / len(latencies) if latencies else 0,
#                     "jitter_ms": jitter
#                 },
#                 "sensor_metrics": {
#                     "reading_rate": {
#                         "current_rps": current_rps,
#                         "reading_interval_ms": statistics.mean(self.sensor_intervals) * 1000 if self.sensor_intervals else 0,
#                         "total_readings": sum(data['total_readings'] for data in self.readings_by_sensor.values()),
#                         "readings_lost": sum(data['readings_lost'] for data in self.readings_by_sensor.values())
#                     },
#                     "by_sensor": {}
#                 }
#             }
            
#             # Calculate per-sensor metrics
#             for sensor_id, sensor_data in self.readings_by_sensor.items():
#                 readings = list(sensor_data['values'])
#                 if readings:
#                     latest = readings[-1]
#                     metrics["sensor_metrics"]["by_sensor"][sensor_id] = {
#                         "total_readings": sensor_data['total_readings'],
#                         "readings_lost": sensor_data['readings_lost'],
#                         "latest_value": latest['value'],
#                         "min_value": min(readings, key=lambda x: x['timestamp'])['value'],
#                         "max_value": max(readings, key=lambda x: x['timestamp'])['value'],
#                     }
            
#             return metrics

#     def _measure_interface_latency(self, interface: str) -> float:
#         try:
#             result = subprocess.run(
#                 ['ping', '-I', interface, '-c', '1', '-W', '1', '10.45.0.1'],
#                 stdout=subprocess.PIPE,
#                 stderr=subprocess.PIPE,
#                 text=True
#             )
#             if result.returncode == 0:
#                 match = re.search(r'time=([\d.]+)', result.stdout)
#                 if match:
#                     return float(match.group(1))
#             return 0
#         except Exception as e:
#             logger.error(f"Error measuring latency for interface {interface}: {e}")
#             return 0

#     def _monitor_network(self):
#         while True:
#             try:
#                 self._update_interfaces()
#                 sleep(1)
#             except Exception as e:
#                 logger.error(f"Error in network monitor: {e}")
#                 sleep(5)

#     def reset(self):
#         with self.metrics_lock:
#             self.start_time = monotonic()
#             self.packet_timestamps.clear()
#             self.packet_sizes.clear()
#             self.total_packets = 0
#             self.total_bytes = 0
#             self.sensor_readings.clear()
#             self.sensor_intervals.clear()
#             self.sensor_timestamps.clear()
#             self.total_readings = 0
#             self.readings_lost = 0
#             self.last_reading_time = None
#             self.last_sequence_number = -1
#             self.readings_by_sensor.clear()
#             self._prev_stats = {}

import threading
import statistics
import logging
import re
import psutil
import socket
import subprocess
import json
from collections import deque
from time import monotonic, sleep
from typing import Dict, Any, Optional, Deque, Union, Tuple

logger = logging.getLogger(__name__)

class SensorMetricsCalculator:
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.metrics_lock = threading.Lock()
        self.start_time = monotonic()
        
        # Add missing packet timestamp tracking
        self.packet_timestamps = deque(maxlen=window_size)
        
        # Packet capture data
        self.ue_capture = None
        self.upf_capture = None
        self.is_capturing = False
        
        # Packet tracking
        self.packet_stats = {
            'ue_packets': deque(maxlen=window_size),  # [(timestamp, size), ...]
            'upf_packets': deque(maxlen=window_size)  # [(timestamp, size), ...]
        }
        
        # Metrics storage
        self.latencies = deque(maxlen=window_size)
        self.packet_sizes = deque(maxlen=window_size)
        self.total_bytes = 0
        self.total_packets = 0
        self.last_packet_time = None
        
        # Sensor metrics
        self.sensor_readings = deque(maxlen=window_size)
        self.sensor_intervals = deque(maxlen=30)
        self.total_readings = 0
        self.readings_lost = 0
        self.readings_by_sensor = {}
        
        # Start packet capture
        self._start_captures()

    def _start_captures(self):
        """Initialize packet captures on both interfaces"""
        try:
            # Setup UE capture (uesimtun)
            ue_cmd = "tcpdump -i uesimtun0 -n -e -tt 'ip and (src 10.45.0.2 or dst 10.45.0.2)'"
            ue_process = subprocess.Popen(
                ['docker', 'exec', 'ue', 'bash', '-c', ue_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Setup UPF capture (ogstun)
            upf_cmd = "tcpdump -i ogstun -n -e -tt 'ip and (src 10.45.0.1 or dst 10.45.0.1)'"
            upf_process = subprocess.Popen(
                ['docker', 'exec', 'upf', 'bash', '-c', upf_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.ue_capture = ue_process
            self.upf_capture = upf_process
            self.is_capturing = True

            # Start packet processing threads
            threading.Thread(target=self._process_ue_capture, daemon=True).start()
            threading.Thread(target=self._process_upf_capture, daemon=True).start()
            
            logger.info("Packet capture started successfully")
        except Exception as e:
            logger.error(f"Failed to start packet capture: {e}")
            self.is_capturing = False

    def _process_ue_capture(self):
        """Process UE interface packets"""
        while self.is_capturing and self.ue_capture:
            try:
                line = self.ue_capture.stdout.readline().strip()
                if line:
                    # Parse tcpdump output
                    parts = line.split()
                    if len(parts) >= 2:
                        timestamp = float(parts[0])
                        size = int(parts[-1])  # Packet size is typically the last field
                        
                        with self.metrics_lock:
                            self.packet_stats['ue_packets'].append((timestamp, size))
                            self.total_bytes += size
                            self.total_packets += 1
                            self.packet_sizes.append(size)
                            self.last_packet_time = timestamp
                            
                            logger.debug(f"UE packet recorded: time={timestamp}, size={size}")
            except Exception as e:
                logger.error(f"Error processing UE packet: {e}")
                sleep(0.1)

    def _process_upf_capture(self):
        """Process UPF interface packets"""
        while self.is_capturing and self.upf_capture:
            try:
                line = self.upf_capture.stdout.readline().strip()
                if line:
                    # Parse tcpdump output
                    parts = line.split()
                    if len(parts) >= 2:
                        timestamp = float(parts[0])
                        size = int(parts[-1])
                        
                        with self.metrics_lock:
                            self.packet_stats['upf_packets'].append((timestamp, size))
                            
                            # Find matching UE packet and calculate latency
                            if self.packet_stats['ue_packets']:
                                ue_packet = self.packet_stats['ue_packets'][-1]
                                latency = timestamp - ue_packet[0]
                                if latency > 0:
                                    self.latencies.append(latency)
                                    logger.debug(f"Latency recorded: {latency*1000:.2f}ms")
                            
                            logger.debug(f"UPF packet recorded: time={timestamp}, size={size}")
            except Exception as e:
                logger.error(f"Error processing UPF packet: {e}")
                sleep(0.1)

    def record_data_sent(self, data: Any, timestamp: float) -> None:
        """Record application-level data being sent"""
        with self.metrics_lock:
            # Calculate and track packet size
            size = len(json.dumps(data)) if isinstance(data, (dict, list)) else len(str(data))
            self.total_bytes += size
            self.total_packets += 1
            self.packet_sizes.append(size)
            self.packet_timestamps.append(timestamp)
            self.last_packet_time = timestamp
            
            # Track packet in UE stats
            self.packet_stats['ue_packets'].append((timestamp, size))

            if isinstance(data, dict) and 'sensor_id' in data:
                sensor_id = data['sensor_id']
                if sensor_id not in self.readings_by_sensor:
                    self.readings_by_sensor[sensor_id] = {
                        "total_readings": 0,
                        "last_sequence": -1,
                        "readings_lost": 0,
                        "values": deque(maxlen=30),
                        "data_points": deque(maxlen=self.window_size)
                    }
                
                # Update sensor-specific metrics
                self.readings_by_sensor[sensor_id]["total_readings"] += 1
                self.readings_by_sensor[sensor_id]["values"].append({
                    "timestamp": timestamp,
                    "value": data.copy()
                })
                self.readings_by_sensor[sensor_id]["data_points"].append({
                    "timestamp": timestamp,
                    "size": size,
                    "type": "sent"
                })
                
                # Calculate and update intervals
                if len(self.readings_by_sensor[sensor_id]["values"]) >= 2:
                    values = list(self.readings_by_sensor[sensor_id]["values"])
                    interval = values[-1]["timestamp"] - values[-2]["timestamp"]
                    if interval > 0:
                        self.sensor_intervals.append(interval)
                
                # Update overall sensor readings
                self.sensor_readings.append({
                    "sensor_id": sensor_id,
                    "timestamp": timestamp,
                    "data": data.copy()
                })
                self.total_readings += 1

                logger.debug(f"Recorded sent data for sensor {sensor_id}: {size} bytes at {timestamp}")

    def record_data_received(self, data: Any, timestamp: float, content_type: str) -> None:
        """Record application-level data being received"""
        with self.metrics_lock:
            # Calculate and track packet size
            size = len(json.dumps(data)) if isinstance(data, (dict, list)) else len(str(data))
            self.total_bytes += size
            self.total_packets += 1
            self.packet_sizes.append(size)
            self.packet_timestamps.append(timestamp)
            
            # Track packet in UPF stats
            self.packet_stats['upf_packets'].append((timestamp, size))

            # Calculate latency if we have a corresponding sent packet
            if self.packet_stats['ue_packets']:
                sent_time = self.packet_stats['ue_packets'][-1][0]
                latency = timestamp - sent_time
                if latency > 0:
                    self.latencies.append(latency)

            if isinstance(data, dict) and 'sensor_id' in data:
                sensor_id = data['sensor_id']
                if sensor_id not in self.readings_by_sensor:
                    self.readings_by_sensor[sensor_id] = {
                        "total_readings": 0,
                        "last_sequence": -1,
                        "readings_lost": 0,
                        "values": deque(maxlen=30),
                        "data_points": deque(maxlen=self.window_size)
                    }
                
                # Update sequence tracking and loss detection
                current_sequence = data.get('sequence', 0)
                last_sequence = self.readings_by_sensor[sensor_id]["last_sequence"]
                
                if last_sequence >= 0 and current_sequence > last_sequence + 1:
                    readings_lost = current_sequence - (last_sequence + 1)
                    self.readings_by_sensor[sensor_id]["readings_lost"] += readings_lost
                    self.readings_lost += readings_lost
                    logger.debug(f"Detected {readings_lost} lost readings for sensor {sensor_id}")
                
                self.readings_by_sensor[sensor_id]["last_sequence"] = current_sequence
                self.readings_by_sensor[sensor_id]["values"].append({
                    "timestamp": timestamp,
                    "value": data.copy()
                })
                self.readings_by_sensor[sensor_id]["data_points"].append({
                    "timestamp": timestamp,
                    "size": size,
                    "type": "received"
                })

                # Calculate and update intervals
                if len(self.readings_by_sensor[sensor_id]["values"]) >= 2:
                    values = list(self.readings_by_sensor[sensor_id]["values"])
                    interval = values[-1]["timestamp"] - values[-2]["timestamp"]
                    if interval > 0:
                        self.sensor_intervals.append(interval)

                # Update overall sensor readings
                self.sensor_readings.append({
                    "sensor_id": sensor_id,
                    "timestamp": timestamp,
                    "data": data.copy()
                })
                self.total_readings += 1

                logger.debug(f"Recorded received data for sensor {sensor_id}: {size} bytes at {timestamp}")
                
                # Update last packet time if this is the most recent
                if self.last_packet_time is None or timestamp > self.last_packet_time:
                    self.last_packet_time = timestamp

    def calculate_metrics(self) -> Dict[str, Any]:
        with self.metrics_lock:
            current_time = monotonic()
            elapsed = max(current_time - self.start_time, 0.001)
            
            # Calculate throughput
            throughput = (self.total_bytes * 8) / (elapsed * 1_000_000) if self.total_bytes > 0 else 0
            
            # Calculate latency statistics
            latency_stats = {
                "min_ms": 0,
                "max_ms": 0,
                "avg_ms": 0,
                "jitter_ms": 0
            }
            
            if self.latencies:
                latencies_ms = [l * 1000 for l in self.latencies]
                latency_stats.update({
                    "min_ms": min(latencies_ms),
                    "max_ms": max(latencies_ms),
                    "avg_ms": sum(latencies_ms) / len(latencies_ms),
                    "jitter_ms": self._calculate_jitter(self.latencies)
                })
            
            # Calculate reading rate
            current_rps = 0
            reading_interval_ms = 0
            if self.sensor_intervals:
                intervals = list(self.sensor_intervals)
                if intervals:
                    avg_interval = statistics.mean(intervals)
                    if avg_interval > 0:
                        current_rps = 1 / avg_interval
                        reading_interval_ms = avg_interval * 1000
            
            # Calculate per-sensor statistics
            sensor_stats = {}
            for sensor_id, sensor_data in self.readings_by_sensor.items():
                readings = list(sensor_data["values"])
                if readings:
                    # Calculate sensor-specific metrics
                    reading_values = [r["value"].get("value", 0) for r in readings if "value" in r["value"]]
                    reading_timestamps = [r["timestamp"] for r in readings]
                    
                    sensor_stats[sensor_id] = {
                        "total_readings": sensor_data["total_readings"],
                        "readings_lost": sensor_data["readings_lost"],
                        "latest_value": readings[-1]["value"],
                        "metrics": {
                            "min_value": min(reading_values) if reading_values else 0,
                            "max_value": max(reading_values) if reading_values else 0,
                            "avg_value": statistics.mean(reading_values) if reading_values else 0,
                            "std_dev": statistics.stdev(reading_values) if len(reading_values) > 1 else 0
                        },
                        "timing": {
                            "first_reading": reading_timestamps[0] if reading_timestamps else 0,
                            "last_reading": reading_timestamps[-1] if reading_timestamps else 0,
                            "avg_interval_ms": (
                                statistics.mean([j-i for i, j in zip(reading_timestamps[:-1], reading_timestamps[1:])])
                                * 1000 if len(reading_timestamps) > 1 else 0
                            )
                        }
                    }
            
            # Build complete metrics dictionary
            metrics = {
                "throughput": {
                    "total_mbps": throughput,
                    "bytes_per_second": self.total_bytes / elapsed if elapsed > 0 else 0,
                    "total_bytes": self.total_bytes,
                    "packets_per_second": self.total_packets / elapsed if elapsed > 0 else 0,
                    "total_packets": self.total_packets
                },
                "latency": latency_stats,
                "sensor_metrics": {
                    "reading_rate": {
                        "current_rps": current_rps,
                        "reading_interval_ms": reading_interval_ms,
                        "total_readings": self.total_readings,
                        "readings_lost": self.readings_lost,
                        "reading_loss_percentage": (
                            (self.readings_lost / max(self.total_readings, 1)) * 100 
                            if self.total_readings > 0 else 0
                        )
                    },
                    "packet_sizes": {
                        "min_bytes": min(self.packet_sizes) if self.packet_sizes else 0,
                        "max_bytes": max(self.packet_sizes) if self.packet_sizes else 0,
                        "avg_bytes": statistics.mean(self.packet_sizes) if self.packet_sizes else 0
                    },
                    "by_sensor": sensor_stats
                },
                "general": {
                    "elapsed_time": elapsed,
                    "start_time": self.start_time,
                    "current_time": current_time
                }
            }
            
            # Add window statistics if available
            if self.packet_sizes:
                window_stats = {
                    "window_size": self.window_size,
                    "current_window": len(self.packet_sizes),
                    "window_throughput_mbps": (
                        sum(self.packet_sizes) * 8 / 
                        (max(current_time - min(self.packet_timestamps), 0.001) * 1_000_000)
                        if self.packet_timestamps else 0
                    )
                }
                metrics["throughput"].update(window_stats)
            
            logger.debug(f"Calculated metrics: {metrics}")
            return metrics

    def _get_sensor_metrics(self) -> Dict[str, Any]:
        sensor_metrics = {}
        for sensor_id, sensor_data in self.readings_by_sensor.items():
            readings = list(sensor_data["values"])
            if readings:
                sensor_metrics[sensor_id] = {
                    "total_readings": sensor_data["total_readings"],
                    "readings_lost": sensor_data["readings_lost"],
                    "latest_value": readings[-1]["value"],
                    "min_value": min(readings, key=lambda x: x["value"].get("sequence", 0))["value"],
                    "max_value": max(readings, key=lambda x: x["value"].get("sequence", 0))["value"]
                }
        return sensor_metrics

    def _calculate_jitter(self, latencies: deque) -> float:
        if len(latencies) < 2:
            return 0.0
        
        jitter = 0.0
        prev_latency = None
        for latency in latencies:
            if prev_latency is not None:
                variation = abs(latency - prev_latency)
                jitter = jitter + (variation - jitter) / 16
            prev_latency = latency
        
        return jitter * 1000

    def reset(self):
        """Reset all metrics"""
        with self.metrics_lock:
            # Stop current captures
            self.is_capturing = False
            if self.ue_capture:
                self.ue_capture.terminate()
            if self.upf_capture:
                self.upf_capture.terminate()
            
            # Reset all metrics
            self.start_time = monotonic()
            self.packet_timestamps.clear()  # Add this line
            self.packet_stats['ue_packets'].clear()
            self.packet_stats['upf_packets'].clear()
            self.latencies.clear()
            self.packet_sizes.clear()
            self.total_bytes = 0
            self.total_packets = 0
            self.last_packet_time = None
            self.sensor_readings.clear()
            self.sensor_intervals.clear()
            self.total_readings = 0
            self.readings_lost = 0
            self.readings_by_sensor.clear()
            
            # Restart captures
            self._start_captures()

    def __del__(self):
        """Cleanup"""
        self.is_capturing = False
        if self.ue_capture:
            self.ue_capture.terminate()
        if self.upf_capture:
            self.upf_capture.terminate()