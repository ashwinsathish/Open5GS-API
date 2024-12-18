import yaml
import requests
import subprocess
import logging
import os
from urllib.parse import urljoin
import shutil
from typing import Dict, Any, Optional
from ruamel.yaml import YAML
from .exceptions import ConfigurationError, CommunicationError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AMBRDirection:
    def __init__(self, parent, direction):
        self.parent = parent
        self.direction = direction
        self.value = None
        self.unit = None

    def __call__(self, value: int, unit: int):
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
        self.index = None
        self.arp = ARP(self)

    def __call__(self, index: int):
        self.index = index
        return self

class ARP:
    def __init__(self, parent):
        self.parent = parent
        self.priority_level = None
        self.pre_emption_vulnerability = None
        self.pre_emption_capability = None

    def __call__(self, priority_level: int, pre_emption_vulnerability: int, pre_emption_capability: int):
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
        self.flow = []

    def add_flow(self, direction: int, description: str):
        self.flow.append({"direction": direction, "description": description})

class Session:
    def __init__(self, parent, name):
        self.parent = parent
        self.name = name
        self.type = 1  
        self.ambr = AMBR(self)
        self.qos = QoS(self)
        self.arp = ARP(self)
        self.pcc_rule = [PccRule(self), PccRule(self)]  

class Policy:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.indent(mapping=2, sequence=4, offset=2)
        self.config = None
        self.sessions = {}
        self._last_modified_time = None

    def _ensure_config_loaded(self, force_reload=False):
        if not self.config_path:
            raise ConfigurationError("Configuration path not set")
        if not os.path.exists(self.config_path):
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        
        current_modified_time = os.path.getmtime(self.config_path)
        if force_reload or self.config is None or current_modified_time != self._last_modified_time:
            self.config = self._read_config()
            self._load_sessions()
            self._last_modified_time = current_modified_time

    def _read_config(self):
        with open(self.config_path, 'r') as file:
            return self.yaml.load(file)

    def _load_sessions(self):
        self.sessions.clear()
        for policy in self.config['pcf']['policy']:
            for slice_config in policy['slice']:
                for session_config in slice_config['session']:
                    session = Session(self, session_config['name'])
                    session.type = session_config['type']
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
                            pcc_rule.flow = pcc_rule_config['flow']
                    
                    self.sessions[session.name] = session

    def set_config_path(self, config_path: str):
        self.config_path = config_path
        self._ensure_config_loaded(force_reload=True)

    def session(self, name):
        self._ensure_config_loaded()
        if name not in self.sessions:
            self.sessions[name] = Session(self, name)
        return self.sessions[name]

    def add_session(self, name):
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

    def remove_session(self, name):
        self._ensure_config_loaded()
        if name not in self.sessions:
            raise ConfigurationError(f"Session '{name}' does not exist")
        
        del self.sessions[name]

        for policy in self.config['pcf']['policy']:
            for slice_config in policy['slice']:
                slice_config['session'] = [s for s in slice_config['session'] if s['name'] != name]

    def list_sessions(self):
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

    def get_session_details(self, name: str):
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
            raise CommunicationError(f"Error sending data: {str(e)}")

    def receive_data(self, endpoint: str) -> Dict[str, Any]:
        try:
            response = requests.get(f"{self.base_url}/{endpoint}")
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise CommunicationError(f"Error receiving data: {str(e)}")

class UEInterface(CommunicationInterface):
    pass

class UPFInterface(CommunicationInterface):
    pass

class Open5GS:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Open5GS, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.policy = Policy()
        self.ue_base_url = "http://10.10.0.132:8080"
        self.upf_base_url = "http://10.10.0.112:8081"

    def set_config_path(self, config_path: str):
        self.policy.set_config_path(config_path)

    def reload_config(self):
        self.policy._ensure_config_loaded(force_reload=True)

    def ue(self, endpoint: str) -> str:
        return urljoin(self.ue_base_url, endpoint)

    def upf(self, endpoint: str) -> str:
        return urljoin(self.upf_base_url, endpoint)

    def send_data(self, url: str, data: Any) -> Dict[str, Any]:
        try:
            response = requests.post(url, data=data)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise CommunicationError(f"Error sending data: {str(e)}")

    def receive_data(self, url: str) -> Any:
        try:
            response = requests.get(url)
            if response.status_code == 204:
                return None
            response.raise_for_status()
            content_type = response.headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                return response.json()
            else:
                return response.content
        except requests.RequestException as e:
            raise CommunicationError(f"Error receiving data: {str(e)}")
    
    def list_sessions(self):
        return self.policy.list_sessions()

    def rename_session(self, old_name: str, new_name: str):
        self.policy.rename_session(old_name, new_name)

    def get_session_details(self, name: str):
        return self.policy.get_session_details(name)

    def update_pcf(self):
        self.policy.update_config()
        logger.info("PCF YAML file updated successfully")

    def update_config(self):
        self._restart_pcf_service()

    def run_background_nodes(self):
        self._run_container_scripts()

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
        
    def _run_container_scripts(self):
        try:
            logger.info("Running scripts in UE and UPF containers...")
            
            tmux_available = shutil.which('tmux') is not None
            
            if tmux_available:
                try:
                    subprocess.run(['tmux', 'list-sessions'], check=True, capture_output=True)
                    use_tmux = True
                except subprocess.CalledProcessError:
                    logger.warning("tmux server is not running. Will run scripts without tmux.")
                    use_tmux = False
            else:
                logger.warning("tmux is not available. Will run scripts without tmux.")
                use_tmux = False

            ue_command = 'docker exec ue bash -c "sh init_script.sh && python3 auto-ue-api.py"'
            upf_command = 'docker exec upf bash -c "cd src/upf && sh init_script.sh && python3 upf-api.py"'

            if use_tmux:
                subprocess.Popen(['tmux', 'new-window', '-n', 'ue', ue_command], start_new_session=True)
                subprocess.Popen(['tmux', 'new-window', '-n', 'upf', upf_command])
                logger.info("Scripts started successfully in tmux sessions")
            else:
                subprocess.Popen(ue_command, shell=True)
                subprocess.Popen(upf_command, shell=True)
                logger.info("Scripts started successfully without tmux")

        except Exception as e:
            logger.error(f"Failed to run container scripts: {str(e)}")
            raise ConfigurationError(f"Failed to run container scripts: {str(e)}")

open5gs = Open5GS()