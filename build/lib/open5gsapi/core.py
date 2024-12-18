import json
import re
import threading
import yaml
import requests
import subprocess
import logging
from ruamel.yaml import YAML
import os
from urllib.parse import urljoin
import shutil
from typing import Dict, Any, Optional, List, Union, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import time
from requests.exceptions import RequestException
from .metrics import NetworkMetricsCalculator
from .sensor_metrics import SensorMetricsCalculator 
from .exceptions import ConfigurationError, CommunicationError, ValidationError


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def validate_input(value: Any, allowed_values: List[Any], field: str):
    if value not in allowed_values:
        raise ValidationError(f"Invalid value for {field}", field, value, allowed_values)

class AMBRDirection:
    def __init__(self, parent, direction: str):
        self.parent = parent
        self.direction = direction
        self.value: Optional[int] = None
        self.unit: Optional[int] = None

    def __call__(self, value: int, unit: int):
        validate_input(unit, [0, 1, 2, 3, 4], f"{self.direction} AMBR unit")
        self.value = value
        self.unit = unit
        return self

class AMBR:
    def __init__(self, parent):
        self.parent = parent
        self.downlink = AMBRDirection(self, 'downlink')
        self.uplink = AMBRDirection(self, 'uplink')

class QoS:
    def __init__(self, parent):
        self.parent = parent
        self.index: Optional[int] = None
        self.arp = ARP(self)

    def __call__(self, index: int):
        allowed_indices = [1, 2, 3, 4, 65, 66, 67, 75, 71, 72, 73, 74, 76, 5, 6, 7, 8, 9, 69, 70, 79, 80, 82, 83, 84, 85, 86]
        validate_input(index, allowed_indices, "QoS index")
        self.index = index
        return self

class ARP:
    def __init__(self, parent):
        self.parent = parent
        self.priority_level: Optional[int] = None
        self.pre_emption_vulnerability: Optional[int] = None
        self.pre_emption_capability: Optional[int] = None

    def __call__(self, priority_level: int, pre_emption_vulnerability: int, pre_emption_capability: int):
        validate_input(priority_level, range(1, 16), "ARP priority level")
        validate_input(pre_emption_vulnerability, [1, 2], "ARP pre-emption vulnerability")
        validate_input(pre_emption_capability, [1, 2], "ARP pre-emption capability")
        self.priority_level = priority_level
        self.pre_emption_vulnerability = pre_emption_vulnerability
        self.pre_emption_capability = pre_emption_capability
        return self

class PccRule:
    def __init__(self, parent):
        self.parent = parent
        self.qos = QoS(self)
        self.mbr = AMBR(self)
        self.gbr = AMBR(self)
        self.flow: List[Dict[str, Union[int, str]]] = []

    def add_flow(self, direction: int, description: str):
        validate_input(direction, [1, 2], "Flow direction")
        self.flow.append({"direction": direction, "description": description})

class Session:
    def __init__(self, parent, name: str):
        self.parent = parent
        self.name = name
        self.type: int = 1
        self.ambr = AMBR(self)
        self.qos = QoS(self)
        self.arp = ARP(self)
        self.pcc_rule: List[PccRule] = [PccRule(self), PccRule(self)]

    def set_type(self, session_type: int):
        validate_input(session_type, [1, 2, 3], "Session type")
        self.type = session_type

class Policy:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        self.config: Optional[Dict[str, Any]] = None
        self.sessions: Dict[str, Session] = {}
        self._last_modified_time: Optional[float] = None

    def _ensure_config_loaded(self, force_reload: bool = False):
        if not self.config_path:
            raise ConfigurationError("Configuration path not set")
        if not os.path.exists(self.config_path):
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        
        current_modified_time = os.path.getmtime(self.config_path)
        if force_reload or self.config is None or current_modified_time != self._last_modified_time:
            self.config = self._read_config()
            self._load_sessions()
            self._last_modified_time = current_modified_time

    def _read_config(self) -> Dict[str, Any]:
        with open(self.config_path, 'r') as file:
            return self.yaml.load(file)

    def _load_sessions(self):
        self.sessions.clear()
        for policy in self.config['pcf']['policy']:
            for slice_config in policy['slice']:
                for session_config in slice_config['session']:
                    session = Session(self, session_config['name'])
                    session.set_type(session_config['type'])
                    session.ambr.downlink(value=session_config['ambr']['downlink']['value'],
                                          unit=session_config['ambr']['downlink']['unit'])
                    session.ambr.uplink(value=session_config['ambr']['uplink']['value'],
                                        unit=session_config['ambr']['uplink']['unit'])
                    session.qos(index=session_config['qos']['index'])
                    session.qos.arp(priority_level=session_config['qos']['arp']['priority_level'],
                                    pre_emption_vulnerability=session_config['qos']['arp']['pre_emption_vulnerability'],
                                    pre_emption_capability=session_config['qos']['arp']['pre_emption_capability'])
                    
                    for i, pcc_rule_config in enumerate(session_config.get('pcc_rule', [])):
                        if i < len(session.pcc_rule):
                            pcc_rule = session.pcc_rule[i]
                            pcc_rule.qos(index=pcc_rule_config['qos']['index'])
                            pcc_rule.qos.arp(priority_level=pcc_rule_config['qos']['arp']['priority_level'],
                                             pre_emption_vulnerability=pcc_rule_config['qos']['arp']['pre_emption_vulnerability'],
                                             pre_emption_capability=pcc_rule_config['qos']['arp']['pre_emption_capability'])
                            pcc_rule.mbr.downlink(value=pcc_rule_config['qos']['mbr']['downlink']['value'],
                                                  unit=pcc_rule_config['qos']['mbr']['downlink']['unit'])
                            pcc_rule.mbr.uplink(value=pcc_rule_config['qos']['mbr']['uplink']['value'],
                                                unit=pcc_rule_config['qos']['mbr']['uplink']['unit'])
                            pcc_rule.gbr.downlink(value=pcc_rule_config['qos']['gbr']['downlink']['value'],
                                                  unit=pcc_rule_config['qos']['gbr']['downlink']['unit'])
                            pcc_rule.gbr.uplink(value=pcc_rule_config['qos']['gbr']['uplink']['value'],
                                                unit=pcc_rule_config['qos']['gbr']['uplink']['unit'])
                            for flow in pcc_rule_config['flow']:
                                pcc_rule.add_flow(flow['direction'], flow['description'])
                    
                    self.sessions[session.name] = session

    def set_config_path(self, config_path: str):
        self.config_path = config_path
        self._ensure_config_loaded(force_reload=True)

    def session(self, name: str) -> Session:
        self._ensure_config_loaded()
        if name not in self.sessions:
            self.sessions[name] = Session(self, name)
        return self.sessions[name]

    def add_session(self, name: str) -> Session:
        self._ensure_config_loaded()
        if name in self.sessions:
            raise ConfigurationError(f"Session '{name}' already exists")
        
        new_session = Session(self, name)
        self.sessions[name] = new_session

        new_session_config = {
            'name': name,
            'type': 1,
            'ambr': {
                'downlink': {'value': 1, 'unit': 0},
                'uplink': {'value': 1, 'unit': 0}
            },
            'qos': {
                'index': 9,
                'arp': {
                    'priority_level': 8,
                    'pre_emption_vulnerability': 1,
                    'pre_emption_capability': 1
                }
            },
            'pcc_rule': [
                {
                    'qos': {
                        'index': 9,
                        'arp': {
                            'priority_level': 8,
                            'pre_emption_vulnerability': 1,
                            'pre_emption_capability': 1
                        },
                        'mbr': {
                            'downlink': {'value': 1, 'unit': 0},
                            'uplink': {'value': 1, 'unit': 0}
                        },
                        'gbr': {
                            'downlink': {'value': 1, 'unit': 0},
                            'uplink': {'value': 1, 'unit': 0}
                        }
                    },
                    'flow': [
                        {'direction': 2, 'description': 'permit out ip from any to assigned'},
                        {'direction': 1, 'description': 'permit out ip from any to assigned'}
                    ]
                }
            ]
        }

        for policy in self.config['pcf']['policy']:
            for slice_config in policy['slice']:
                slice_config['session'].append(new_session_config)
                break
        
        return new_session

    def remove_session(self, name: str):
        self._ensure_config_loaded()
        if name not in self.sessions:
            raise ConfigurationError(f"Session '{name}' does not exist")
        
        del self.sessions[name]

        for policy in self.config['pcf']['policy']:
            for slice_config in policy['slice']:
                slice_config['session'] = [s for s in slice_config['session'] if s['name'] != name]

    def list_sessions(self) -> List[str]:
        self._ensure_config_loaded()
        return list(self.sessions.keys())

    def rename_session(self, old_name: str, new_name: str):
        self._ensure_config_loaded()
        if old_name not in self.sessions:
            raise ConfigurationError(f"Session '{old_name}' does not exist")
        if new_name in self.sessions:
            raise ConfigurationError(f"Session '{new_name}' already exists")
        
        self.sessions[new_name] = self.sessions.pop(old_name)
        self.sessions[new_name].name = new_name

        for policy in self.config['pcf']['policy']:
            for slice_config in policy['slice']:
                for session in slice_config['session']:
                    if session['name'] == old_name:
                        session['name'] = new_name
                        return 

    def get_session_details(self, name: str) -> Dict[str, Any]:
        self._ensure_config_loaded()
        if name not in self.sessions:
            raise ConfigurationError(f"Session '{name}' does not exist")
        
        for policy in self.config['pcf']['policy']:
            for slice_config in policy['slice']:
                for session in slice_config['session']:
                    if session['name'] == name:
                        return session
        
        raise ConfigurationError(f"Session '{name}' not found in configuration")

    def update_config(self):
        self._ensure_config_loaded()
        for policy in self.config['pcf']['policy']:
            for slice_config in policy['slice']:
                for session_config in slice_config['session']:
                    if session_config['name'] in self.sessions:
                        session = self.sessions[session_config['name']]
                        
                        if 'type' in session_config:
                            session_config['type'] = session.type
                        
                        if 'ambr' in session_config:
                            if 'downlink' in session_config['ambr']:
                                if session.ambr.downlink.value is not None:
                                    session_config['ambr']['downlink']['value'] = session.ambr.downlink.value
                                if session.ambr.downlink.unit is not None:
                                    session_config['ambr']['downlink']['unit'] = session.ambr.downlink.unit
                            if 'uplink' in session_config['ambr']:
                                if session.ambr.uplink.value is not None:
                                    session_config['ambr']['uplink']['value'] = session.ambr.uplink.value
                                if session.ambr.uplink.unit is not None:
                                    session_config['ambr']['uplink']['unit'] = session.ambr.uplink.unit
                        
                        if 'qos' in session_config:
                            if session.qos.index is not None:
                                session_config['qos']['index'] = session.qos.index
                            if 'arp' in session_config['qos']:
                                if session.qos.arp.priority_level is not None:
                                    session_config['qos']['arp']['priority_level'] = session.qos.arp.priority_level
                                if session.qos.arp.pre_emption_vulnerability is not None:
                                    session_config['qos']['arp']['pre_emption_vulnerability'] = session.qos.arp.pre_emption_vulnerability
                                if session.qos.arp.pre_emption_capability is not None:
                                    session_config['qos']['arp']['pre_emption_capability'] = session.qos.arp.pre_emption_capability

                        if 'pcc_rule' in session_config:
                            for i, pcc_rule_config in enumerate(session_config['pcc_rule']):
                                if i < len(session.pcc_rule):
                                    pcc_rule = session.pcc_rule[i]
                                    if 'qos' in pcc_rule_config:
                                        if pcc_rule.qos.index is not None:
                                            pcc_rule_config['qos']['index'] = pcc_rule.qos.index
                                        if 'arp' in pcc_rule_config['qos']:
                                            if pcc_rule.qos.arp.priority_level is not None:
                                                pcc_rule_config['qos']['arp']['priority_level'] = pcc_rule.qos.arp.priority_level
                                            if pcc_rule.qos.arp.pre_emption_vulnerability is not None:
                                                pcc_rule_config['qos']['arp']['pre_emption_vulnerability'] = pcc_rule.qos.arp.pre_emption_vulnerability
                                            if pcc_rule.qos.arp.pre_emption_capability is not None:
                                                pcc_rule_config['qos']['arp']['pre_emption_capability'] = pcc_rule.qos.arp.pre_emption_capability
                                        if 'mbr' in pcc_rule_config['qos']:
                                            if 'downlink' in pcc_rule_config['qos']['mbr']:
                                                if pcc_rule.mbr.downlink.value is not None:
                                                    pcc_rule_config['qos']['mbr']['downlink']['value'] = pcc_rule.mbr.downlink.value
                                                if pcc_rule.mbr.downlink.unit is not None:
                                                    pcc_rule_config['qos']['mbr']['downlink']['unit'] = pcc_rule.mbr.downlink.unit
                                            if 'uplink' in pcc_rule_config['qos']['mbr']:
                                                if pcc_rule.mbr.uplink.value is not None:
                                                    pcc_rule_config['qos']['mbr']['uplink']['value'] = pcc_rule.mbr.uplink.value
                                                if pcc_rule.mbr.uplink.unit is not None:
                                                    pcc_rule_config['qos']['mbr']['uplink']['unit'] = pcc_rule.mbr.uplink.unit
                                        if 'gbr' in pcc_rule_config['qos']:
                                            if 'downlink' in pcc_rule_config['qos']['gbr']:
                                                if pcc_rule.gbr.downlink.value is not None:
                                                    pcc_rule_config['qos']['gbr']['downlink']['value'] = pcc_rule.gbr.downlink.value
                                                if pcc_rule.gbr.downlink.unit is not None:
                                                    pcc_rule_config['qos']['gbr']['downlink']['unit'] = pcc_rule.gbr.downlink.unit
                                            if 'uplink' in pcc_rule_config['qos']['gbr']:
                                                if pcc_rule.gbr.uplink.value is not None:
                                                    pcc_rule_config['qos']['gbr']['uplink']['value'] = pcc_rule.gbr.uplink.value
                                                if pcc_rule.gbr.uplink.unit is not None:
                                                    pcc_rule_config['qos']['gbr']['uplink']['unit'] = pcc_rule.gbr.uplink.unit
                                    if pcc_rule.flow:
                                        pcc_rule_config['flow'] = pcc_rule.flow

        with open(self.config_path, 'w') as file:
            self.yaml.dump(self.config, file)
            
class CommunicationInterface:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def send_data(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            response = requests.post(f"{self.base_url}/{endpoint}", json=data)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise CommunicationError(f"Error sending data: {str(e)}", endpoint=endpoint)

    def receive_data(self, endpoint: str) -> Dict[str, Any]:
        try:
            response = requests.get(f"{self.base_url}/{endpoint}")
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise CommunicationError(f"Error receiving data: {str(e)}", endpoint=endpoint)

class UEInterface(CommunicationInterface):
    pass

class UPFInterface(CommunicationInterface):
    pass

class Open5GS:
    _instance = None
    _update_pcf_complete = False
    _update_config_complete = False
    _run_background_nodes_complete = False
    _background_process_status = {
        'ue_api_ready': False,
        'upf_api_ready': False,
        'error_message': None
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Open5GS, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.policy = Policy()
        self.ue_base_url = "http://10.10.0.132:8080"
        self.upf_base_url = "http://10.10.0.112:8081"
        self._process_monitor = None
        self.env_path = None
        self._env_config = None
        self._last_env_modified_time = None
        self.ue_interface = UEInterface(self.ue_base_url)
        self.upf_interface = UPFInterface(self.upf_base_url)
        self.metrics = NetworkMetricsCalculator()
        self.sensor_metrics = SensorMetricsCalculator() 
        self._packet_id = 0
        self._packet_id_lock = threading.Lock()

    def set_config_path(self, config_path: str):
        self.policy.set_config_path(config_path)

    def reload_config(self):
        self.policy._ensure_config_loaded(force_reload=True)

    def set_env_path(self, env_path: str):
        """Set the path to the .env file and load it"""
        if not os.path.exists(env_path):
            raise ConfigurationError(f"Environment file not found: {env_path}")
        self.env_path = env_path
        self._ensure_env_loaded()

    def _ensure_env_loaded(self, force_reload: bool = False):
        """Ensure the environment file is loaded and up to date"""
        if not self.env_path:
            raise ConfigurationError("Environment file path not set")
        
        current_modified_time = os.path.getmtime(self.env_path)
        if (force_reload or self._env_config is None or 
            current_modified_time != self._last_env_modified_time):
            self._env_config = self._read_env_file()
            self._last_env_modified_time = current_modified_time

    def _read_env_file(self) -> Dict[str, str]:
        """Read and parse the .env file"""
        env_config = {}
        try:
            with open(self.env_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        try:
                            key, value = line.split('=', 1)
                            env_config[key.strip()] = value.strip()
                        except ValueError:
                            continue
            return env_config
        except Exception as e:
            raise ConfigurationError(f"Failed to read environment file: {str(e)}")

    def _write_env_file(self):
        """Write the current configuration back to the .env file"""
        try:
            with open(self.env_path, 'w') as file:
                for key, value in self._env_config.items():
                    file.write(f"{key}={value}\n")
        except Exception as e:
            raise ConfigurationError(f"Failed to write environment file: {str(e)}")

    def get_num_ues(self) -> int:
        """Get the current number of UEs configured"""
        self._ensure_env_loaded()
        try:
            return int(self._env_config.get('NUM_UES', 1))
        except ValueError:
            logger.warning("Invalid NUM_UES value in .env file, defaulting to 1")
            return 1

    def set_num_ues(self, num_ues: int):
        if self._update_config_complete:
            raise ConfigurationError(
                "Cannot modify NUM_UES after update_config() has been called. "
                "Please set NUM_UES before calling update_config()."
            )

        if not isinstance(num_ues, int) or num_ues < 1:
            raise ValueError("Number of UEs must be a positive integer")

        self._ensure_env_loaded()
        
        self._env_config['NUM_UES'] = str(num_ues)
        
        self._write_env_file()
        logger.info(f"Updated NUM_UES to {num_ues}")

    def reload_env(self):

        if not self.env_path:
            raise ConfigurationError("Environment file path not set")
        self._ensure_env_loaded(force_reload=True)
        logger.info("Environment configuration reloaded successfully")

    def reload_env_config(self):
        """Alias for reload_env() to maintain naming consistency with reload_config()"""
        self.reload_env()

    def ue(self, endpoint: str) -> str:
        return urljoin(self.ue_base_url, endpoint)

    def upf(self, endpoint: str) -> str:
        return urljoin(self.upf_base_url, endpoint)

    def _check_api_endpoint(self, url: str, timeout: int = 1) -> bool:
        try:
            response = requests.get(url, timeout=timeout)
            return response.status_code in [200, 204]
        except RequestException:
            return False

    def _check_ue_interfaces(self) -> Tuple[bool, Optional[str]]:
        """Check if UE API endpoints are running properly"""
        try:
            result = subprocess.run(
                ["docker", "exec", "ue", "python3", "-c", 
                "import netifaces; tuns = [i for i in netifaces.interfaces() if i.startswith('uesimtun')]; print(len(tuns))"],
                capture_output=True,
                text=True
            )
            
            try:
                num_tun_interfaces = int(result.stdout.strip())
                if num_tun_interfaces == 0:
                    # No TUN interfaces - real error case
                    return False, "UE API endpoints not accessible"
                
                # TUN interfaces exist, try to reach any of the APIs
                for i in range(num_tun_interfaces):
                    url = f"http://10.10.0.132:{8080 + i}/get_ue_ip"
                    try:
                        response = requests.get(url)
                        if response.status_code == 200:
                            return True, None
                    except requests.RequestException:
                        continue
                
                # TUN interfaces exist but no API responding yet
                return False, "Waiting for UE API endpoints to start..."
                
            except ValueError:
                return False, "UE API endpoints not accessible"
                
        except Exception as e:
            return False, f"Error checking UE interfaces: {str(e)}"

    def _check_upf_api(self) -> Tuple[bool, Optional[str]]:
        try:
            response = requests.get(f"{self.upf_base_url}/receive")
            return response.status_code in [200, 204], None
        except RequestException:
            return False, "UPF API endpoint not accessible"
        except Exception as e:
            return False, f"Error checking UPF API: {str(e)}"

    def _monitor_background_processes(self, timeout: int = 100):
        """Monitor background processes until they're ready or timeout occurs"""
        start_time = time.time()
        check_interval = 1  
        
        while (time.time() - start_time) < timeout:
            # Check UE interfaces
            ue_ready, ue_error = self._check_ue_interfaces()
            self._background_process_status['ue_api_ready'] = ue_ready
            
            # Check UPF API
            upf_ready, upf_error = self._check_upf_api()
            self._background_process_status['upf_api_ready'] = upf_ready
            
            # Update error message if any
            if ue_error:
                self._background_process_status['error_message'] = ue_error
            elif upf_error:
                self._background_process_status['error_message'] = upf_error
            else:
                self._background_process_status['error_message'] = None
            
            # Check if both are ready
            if ue_ready and upf_ready:
                self._run_background_nodes_complete = True
                logger.info("All background nodes are running successfully")
                return
            
            time.sleep(check_interval)
        
        # If we get here, we've timed out
        self._background_process_status['error_message'] = "Timeout waiting for background nodes to start"
        logger.error(self._background_process_status['error_message'])

    def _get_next_packet_id(self) -> int:
        with self._packet_id_lock:
            self._packet_id += 1
            return self._packet_id
        
    def get_sensor_metrics(self) -> Dict[str, Any]:
        """Get current sensor performance metrics"""
        try:
            return self.sensor_metrics.calculate_metrics()
        except Exception as e:
            logger.error(f"Error calculating sensor metrics: {e}")
            raise

    def reset_sensor_metrics(self) -> None:
        """Reset all sensor metrics"""
        self.sensor_metrics = SensorMetricsCalculator()
        logger.info("Sensor metrics reset")

    def send_data(self, endpoint: str, data: Any, port_offset: int = 0) -> Dict[str, Any]:
        try:
            if port_offset:
                if '://' in endpoint:
                    scheme, rest = endpoint.split('://', 1)
                    host, path = rest.split('/', 1)
                    host_parts = host.split(':')
                    base_url = f"{scheme}://{host_parts[0]}"
                    url = f"{base_url}:{self.base_port + port_offset}/{path}"
                else:
                    raise CommunicationError("Invalid endpoint URL format", endpoint=endpoint)
            else:
                url = endpoint

            logger.debug(f"Sending data to URL: {url}")
            current_time = time.monotonic()

            # Add send timestamp to sensor data
            if isinstance(data, dict) and "sensor_id" in data:
                data_to_send = data.copy()
                data_to_send['_send_timestamp'] = current_time
                self.sensor_metrics.record_data_sent(data_to_send, current_time)
            else:
                # For video frame data, prepend timestamp
                if isinstance(data, bytes):
                    timestamp_bytes = str(current_time).encode('utf-8')
                    data_to_send = b'TIME:' + timestamp_bytes + b':' + data
                else:
                    data_to_send = data
                self.metrics.record_data_sent(data_to_send, current_time)

            # Send data
            if isinstance(data_to_send, (dict, list)):
                response = requests.post(url, json=data_to_send)
            else:
                response = requests.post(url, data=data_to_send)
            
            response.raise_for_status()
            return response.json()
                
        except requests.RequestException as e:
            logger.error(f"Error sending data: {str(e)}")
            raise CommunicationError(f"Error sending data: {str(e)}", endpoint=endpoint)

    def receive_data(self, endpoint: str) -> Any:
        try:
            response = requests.get(endpoint)
            receive_time = time.monotonic()
            
            if response.status_code == 204:
                return None
                
            response.raise_for_status()
            content_type = response.headers.get('content-type', '')
            content = response.content
            
            if 'application/json' in content_type:
                try:
                    data = response.json()
                    
                    # Handle sensor data
                    sensor_data = None
                    if isinstance(data, dict):
                        if 'sensor_id' in data:
                            sensor_data = data
                        elif 'data' in data and isinstance(data['data'], dict) and 'sensor_id' in data['data']:
                            sensor_data = data['data']
                            sensor_data['source_ip'] = data.get('source_ip')
                    
                    if sensor_data and '_send_timestamp' in sensor_data:
                        self.sensor_metrics.record_data_received(sensor_data, receive_time, content_type)
                        return data
                    else:
                        self.metrics.record_data_received(content, receive_time, content_type)
                        return data
                        
                except json.JSONDecodeError:
                    return content
            else:
                # Handle video frame data with timestamp
                if isinstance(content, bytes) and content.startswith(b'TIME:'):
                    try:
                        # Extract timestamp and original data
                        _, timestamp_data = content.split(b'TIME:', 1)
                        send_time_str, frame_data = timestamp_data.split(b':', 1)
                        send_time = float(send_time_str.decode('utf-8'))
                        
                        # Create frame info for metrics
                        frame_info = {
                            '_send_timestamp': send_time,
                            'data': frame_data
                        }
                        
                        self.metrics.record_data_received(frame_info, receive_time, content_type)
                        return frame_data  # Return original frame data
                    except Exception as e:
                        logger.error(f"Error processing frame timestamp: {e}")
                        self.metrics.record_data_received(content, receive_time, content_type)
                        return content
                else:
                    self.metrics.record_data_received(content, receive_time, content_type)
                    return content
                    
        except requests.RequestException as e:
            logger.error(f"Error receiving data: {str(e)}")
            raise CommunicationError(f"Error receiving data: {str(e)}", endpoint=endpoint)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current network performance metrics"""
        try:
            return self.metrics.calculate_metrics()
        except Exception as e:
            logger.error(f"Error calculating metrics: {e}")
            raise

    def reset_metrics(self) -> None:
        """Reset all network metrics"""
        self.metrics = NetworkMetricsCalculator()
        logger.info("Network metrics reset")

    def get_frame_metrics(self) -> Optional[Dict[str, Any]]:
        """Get frame-specific metrics if available"""
        try:
            metrics = self.metrics.calculate_metrics()
            return metrics.get('frame_metrics')
        except Exception as e:
            logger.error(f"Error getting frame metrics: {e}")
            return None

    def get_throughput(self) -> float:
        """Get current throughput in Mbps"""
        try:
            return self.metrics.calculate_metrics()['throughput']['total_mbps']
        except Exception as e:
            logger.error(f"Error getting throughput: {e}")
            return 0.0

    def get_latency_stats(self) -> Dict[str, float]:
        """Get current latency statistics in milliseconds"""
        try:
            return self.metrics.calculate_metrics()['latency']
        except Exception as e:
            logger.error(f"Error getting latency stats: {e}")
            return {
                "min_ms": 0,
                "max_ms": 0,
                "avg_ms": 0,
                "jitter_ms": 0
            }
    
    def list_sessions(self) -> List[str]:
        return self.policy.list_sessions()

    def rename_session(self, old_name: str, new_name: str):
        self.policy.rename_session(old_name, new_name)

    def get_session_details(self, name: str) -> Dict[str, Any]:
        return self.policy.get_session_details(name)

    def update_pcf(self):
        self.policy.update_config()
        self._update_pcf_complete = True
        logger.info("PCF YAML file updated successfully")

    def update_config(self):
        if not self.env_path:
            logger.warning("Environment file path not set. NUM_UES configuration may not be applied.")
        
        self._restart_pcf_service()
        self._update_config_complete = True

    def run_background_nodes(self):
        """Start background nodes and monitor their startup"""
        try:
            self._run_background_nodes_complete = False
            self._background_process_status = {
                'ue_api_ready': False,
                'upf_api_ready': False,
                'error_message': None
            }
            
            logger.info("Checking for successful TUN interface creation...")
            
            if not self._verify_tun_interfaces():
                error_msg = "Failed to verify TUN interface creation within timeout"
                self._background_process_status['error_message'] = error_msg
                logger.error(error_msg)
                return
            
            logger.info("TUN interfaces verified. Starting container scripts...")
            
            upf_command = 'docker exec upf bash -c "cd src/upf && sh init_script.sh && python3 upf-api.py"'
            subprocess.Popen(upf_command, shell=True)
            
            ue_command = 'docker exec ue bash -c "sh init_script.sh && python3 auto-ue-api.py"'
            subprocess.Popen(ue_command, shell=True)
            
            with ThreadPoolExecutor(max_workers=1) as executor:
                self._process_monitor = executor.submit(self._monitor_background_processes)
                
        except Exception as e:
            error_msg = f"Failed to run container scripts: {str(e)}"
            logger.error(error_msg)
            self._background_process_status['error_message'] = error_msg
            raise ConfigurationError(error_msg)

    def _verify_tun_interfaces(self, timeout=30) -> bool:
        """Verify TUN interface creation by checking docker logs"""
        try:
            logger.info("Waiting for TUN interface creation...")
            start_time = time.time()
            
            success_pattern = r"Connection setup for PDU session\[1\] is successful, TUN interface\[uesimtun\d+, .+\] is up\."
            
            # Start reading docker logs
            process = subprocess.Popen(
                ['docker', 'logs', '-f', 'ue'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            while (time.time() - start_time) < timeout:
                line = process.stdout.readline()
                if not line:
                    continue
                
                # Look for success message
                if re.search(success_pattern, line):
                    logger.info("Detected successful TUN interface creation")
                    process.terminate()
                    return True
                    
                # Optional: Log relevant messages for debugging
                if "TUN interface" in line or "PDU session" in line:
                    logger.debug(f"UE log: {line.strip()}")
                    
            # If we get here, we timed out
            process.terminate()
            logger.error(f"Timeout ({timeout}s) reached waiting for TUN interface creation")
            return False

        except Exception as e:
            logger.error(f"Error checking TUN interfaces: {e}")
            return False

    def _check_tmux_server(self) -> bool:
        """Check if tmux server is running"""
        try:
            subprocess.run(['tmux', 'list-sessions'], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def is_update_pcf_complete(self) -> bool:
        return self._update_pcf_complete

    def is_update_config_complete(self) -> bool:
        return self._update_config_complete

    def is_run_background_nodes_complete(self) -> bool:
        """
        Check if background nodes are completely set up and running.
        Returns True only when all UEs are confirmed to be working.
        """
        if self._background_process_status['error_message'] == "No TUN interfaces found":
            return False
        return self._run_background_nodes_complete

    def get_background_process_status(self) -> Dict[str, Any]:
        """Get detailed status of background processes"""
        return {
            'completed': self._run_background_nodes_complete,
            'ue_api_ready': self._background_process_status['ue_api_ready'],
            'upf_api_ready': self._background_process_status['upf_api_ready'],
            'error_message': self._background_process_status['error_message']
        }

    def _restart_pcf_service(self):
        try:
            # Check if Docker containers are running
            result = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True)
            if result.stdout.strip():
                logger.info("Existing Docker containers found. Tearing down...")
                subprocess.run(["docker", "compose", "down", "-t", "1", "-v"], check=True)
            else:
                logger.info("No running Docker containers found.")

            logger.info("Bringing up Docker deployment...")
            subprocess.run(["docker", "compose", "up", "-d"], check=True)

            logger.info("PCF service restarted successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restart PCF service: {str(e)}")
            raise ConfigurationError(f"Failed to restart PCF service: {str(e)}")

    def _check_wireshark_installed(self) -> bool:
            paths = ["/usr/bin/wireshark", "/usr/local/bin/wireshark"]
            return any(os.path.exists(path) for path in paths)
        
    def _get_interface_name(self, ip_address: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["ip", "-o", "addr", "show"], 
                capture_output=True, 
                text=True, 
                check=True
            )
            
            for line in result.stdout.split('\n'):
                if ip_address in line:
                    return line.split()[1]
            return None
        except subprocess.CalledProcessError as e:
            logger.error(f"Error getting interface name: {str(e)}")
            return None

    def _get_display_environment(self) -> dict:
        """Get environment variables needed for GUI applications"""
        env = os.environ.copy()
        if 'DISPLAY' not in env:
            env['DISPLAY'] = ':0'
        
        try:
            subprocess.run(['xhost', '+'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except:
            pass
        
        return env

    def launch_wireshark(self, 
                        ip_address: str = "10.10.0.1", 
                        display_filter: str = "gtp",
                        capture_filter: Optional[str] = None) -> bool:
        try:
            wireshark_cmd = "/usr/bin/wireshark"
            if not os.path.exists(wireshark_cmd):
                raise ConfigurationError("Wireshark not found. Please install via: sudo apt install wireshark")
                
            logger.info(f"Using Wireshark from: {wireshark_cmd}")
            
            interface_name = self._get_interface_name(ip_address)
            if not interface_name:
                raise ConfigurationError(f"No interface found with IP address {ip_address}")
            
            command = [wireshark_cmd, "-i", interface_name, "-k"]
            if display_filter:
                command.extend(["-Y", display_filter])
            if capture_filter:
                command.extend(["-f", capture_filter])
                
            clean_env = {
                'DISPLAY': os.environ.get('DISPLAY', ':0'),
                'HOME': os.environ.get('HOME', ''),
                'USER': os.environ.get('USER', ''),
                'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                'XAUTHORITY': os.environ.get('XAUTHORITY', ''),
                'LANG': os.environ.get('LANG', 'en_US.UTF-8'),
                'LC_ALL': 'C'
            }
            
            if 'LD_LIBRARY_PATH' in clean_env:
                paths = clean_env['LD_LIBRARY_PATH'].split(':')
                clean_paths = [p for p in paths if 'snap' not in p.lower()]
                if clean_paths:
                    clean_env['LD_LIBRARY_PATH'] = ':'.join(clean_paths)
                
            try:
                subprocess.run(['xhost', '+local:'], check=True, 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE)
            except Exception as e:
                logger.warning(f"Could not set xhost permissions: {e}")
                
            process = subprocess.Popen(
                command,
                env=clean_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True
            )
            
            time.sleep(1)  
            
            if process.poll() is None:  
                logger.info(f"Wireshark launched successfully on interface {interface_name}")
                return True
            else:
                stdout, stderr = process.communicate()
                error_msg = (f"Wireshark failed to start.\n"
                            f"Command: {' '.join(command)}\n"
                            f"Environment: {clean_env}\n"
                            f"stdout: {stdout.decode()}\n"
                            f"stderr: {stderr.decode()}")
                raise ConfigurationError(error_msg)
                
        except Exception as e:
            error_msg = f"Failed to launch Wireshark: {str(e)}"
            logger.error(error_msg)
            raise ConfigurationError(error_msg)

    def launch_gtp_wireshark(self) -> bool:
        try:
            return self.launch_wireshark(
                ip_address="10.10.0.1",
                display_filter="gtp"  # Simple GTP filter
            )
        except Exception as e:
            logger.error(f"Failed to launch GTP Wireshark: {e}")
            return False

# Global instance
open5gs = Open5GS()