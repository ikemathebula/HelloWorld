import subprocess
import re
import socket
import platform
import shlex
from typing import Dict, List, Any
import time

class NetworkDiagnostics:
    """Network diagnostic utilities for ping and traceroute operations"""
    
    def __init__(self):
        self.platform = platform.system().lower()
    
    def validate_target(self, target: str) -> bool:
        """Validate if the target is a valid IP address or hostname"""
        try:
            # Sanitize input - only allow alphanumeric, dots, hyphens, and underscores
            if not re.match(r'^[a-zA-Z0-9.-]+$', target):
                return False
            
            # Check for command injection patterns
            dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\']
            if any(char in target for char in dangerous_chars):
                return False
            
            # Try to resolve the hostname/IP
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False
    
    def ping(self, target: str, count: int = 4, timeout: int = 5) -> Dict[str, Any]:
        """
        Perform ping operation and return latency and packet loss statistics
        
        Args:
            target: IP address or hostname to ping
            count: Number of ping packets to send
            timeout: Timeout in seconds for each ping
            
        Returns:
            Dictionary containing ping results
        """
        try:
            # Validate target before processing
            if not self.validate_target(target):
                return {
                    'success': False,
                    'error': "Invalid target: contains unsafe characters or cannot be resolved",
                    'avg_latency': 0,
                    'min_latency': 0,
                    'max_latency': 0,
                    'packet_loss': 100.0
                }
            
            # Construct ping command based on platform with sanitized target
            sanitized_target = shlex.quote(target)
            if self.platform == "windows":
                cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), sanitized_target]
            else:
                cmd = ["ping", "-c", str(count), "-W", str(timeout), sanitized_target]
            
            # Execute ping command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10
            )
            
            if result.returncode == 0:
                return self._parse_ping_output(result.stdout, count)
            else:
                return {
                    'success': False,
                    'error': result.stderr or "Ping failed",
                    'avg_latency': 0,
                    'min_latency': 0,
                    'max_latency': 0,
                    'packet_loss': 100.0
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': "Ping timeout",
                'avg_latency': 0,
                'min_latency': 0,
                'max_latency': 0,
                'packet_loss': 100.0
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'avg_latency': 0,
                'min_latency': 0,
                'max_latency': 0,
                'packet_loss': 100.0
            }
    
    def _parse_ping_output(self, output: str, expected_count: int) -> Dict[str, Any]:
        """Parse ping command output to extract statistics"""
        try:
            lines = output.split('\n')
            
            # Initialize variables
            latencies = []
            packets_sent = expected_count
            packets_received = 0
            
            # Extract individual ping times
            for line in lines:
                if self.platform == "windows":
                    # Windows format: "Reply from x.x.x.x: bytes=32 time=1ms TTL=64"
                    time_match = re.search(r'time[<=](\d+(?:\.\d+)?)ms', line, re.IGNORECASE)
                    if time_match:
                        latencies.append(float(time_match.group(1)))
                        packets_received += 1
                else:
                    # Linux/Mac format: "64 bytes from x.x.x.x: icmp_seq=1 ttl=64 time=1.23 ms"
                    time_match = re.search(r'time=(\d+(?:\.\d+)?)', line)
                    if time_match:
                        latencies.append(float(time_match.group(1)))
                        packets_received += 1
            
            # Parse packet loss from summary
            packet_loss = 0.0
            for line in lines:
                if "packet loss" in line.lower() or "loss" in line.lower():
                    loss_match = re.search(r'(\d+(?:\.\d+)?)%', line)
                    if loss_match:
                        packet_loss = float(loss_match.group(1))
                        break
            
            # If we couldn't parse packet loss, calculate it
            if packet_loss == 0.0 and packets_received < packets_sent:
                packet_loss = ((packets_sent - packets_received) / packets_sent) * 100
            
            # Calculate statistics
            if latencies:
                avg_latency = sum(latencies) / len(latencies)
                min_latency = min(latencies)
                max_latency = max(latencies)
            else:
                avg_latency = min_latency = max_latency = 0
            
            return {
                'success': True,
                'avg_latency': avg_latency,
                'min_latency': min_latency,
                'max_latency': max_latency,
                'packet_loss': packet_loss,
                'packets_sent': packets_sent,
                'packets_received': packets_received,
                'latencies': latencies
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Failed to parse ping output: {str(e)}",
                'avg_latency': 0,
                'min_latency': 0,
                'max_latency': 0,
                'packet_loss': 100.0
            }
    
    def traceroute(self, target: str, max_hops: int = 30, timeout: int = 5) -> Dict[str, Any]:
        """
        Perform traceroute operation to trace network path
        
        Args:
            target: IP address or hostname to trace
            max_hops: Maximum number of hops to trace
            timeout: Timeout in seconds for each hop
            
        Returns:
            Dictionary containing traceroute results
        """
        try:
            # Validate target before processing
            if not self.validate_target(target):
                return {
                    'success': False,
                    'error': "Invalid target: contains unsafe characters or cannot be resolved",
                    'hops': []
                }
            
            # Construct traceroute command based on platform with sanitized target
            sanitized_target = shlex.quote(target)
            if self.platform == "windows":
                cmd = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), sanitized_target]
            else:
                cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), sanitized_target]
            
            # Execute traceroute command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max_hops * timeout + 30
            )
            
            if result.returncode == 0 or result.stdout:
                return self._parse_traceroute_output(result.stdout)
            else:
                return {
                    'success': False,
                    'error': result.stderr or "Traceroute failed",
                    'hops': []
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': "Traceroute timeout",
                'hops': []
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'hops': []
            }
    
    def _parse_traceroute_output(self, output: str) -> Dict[str, Any]:
        """Parse traceroute command output to extract hop information"""
        try:
            lines = output.split('\n')
            hops = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Skip header lines
                if ("traceroute" in line.lower() or 
                    "tracing route" in line.lower() or
                    "over a maximum" in line.lower()):
                    continue
                
                hop_info = self._parse_hop_line(line)
                if hop_info and hop_info['hop'] > 0:
                    hops.append(hop_info)
            
            return {
                'success': True,
                'hops': hops,
                'total_hops': len(hops)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Failed to parse traceroute output: {str(e)}",
                'hops': []
            }
    
    def _parse_hop_line(self, line: str) -> Dict[str, Any]:
        """Parse individual hop line from traceroute output"""
        try:
            if self.platform == "windows":
                # Windows format: "  1     1 ms     1 ms     1 ms  192.168.1.1"
                match = re.match(r'\s*(\d+)\s+(?:(\d+)\s*ms|\*)\s+(?:(\d+)\s*ms|\*)\s+(?:(\d+)\s*ms|\*)\s+(.+)', line)
                if match:
                    hop_num = int(match.group(1))
                    times = [match.group(2), match.group(3), match.group(4)]
                    host_info = match.group(5).strip()
                    
                    # Calculate average latency from non-timeout responses
                    valid_times = [float(t) for t in times if t and t != '*']
                    avg_latency = sum(valid_times) / len(valid_times) if valid_times else 0
                    
                    # Extract IP address
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host_info)
                    ip_addr = ip_match.group(1) if ip_match else host_info
                    
                    return {
                        'hop': hop_num,
                        'ip': ip_addr,
                        'latency': avg_latency,
                        'hostname': host_info if not ip_match else None
                    }
            else:
                # Linux/Mac format: " 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.567 ms  1.890 ms"
                match = re.match(r'\s*(\d+)\s+(.+)', line)
                if match:
                    hop_num = int(match.group(1))
                    hop_data = match.group(2)
                    
                    # Extract IP address
                    ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', hop_data)
                    if not ip_match:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', hop_data)
                    
                    ip_addr = ip_match.group(1) if ip_match else "Unknown"
                    
                    # Extract latency times
                    time_matches = re.findall(r'(\d+(?:\.\d+)?)\s*ms', hop_data)
                    if time_matches:
                        times = [float(t) for t in time_matches]
                        avg_latency = sum(times) / len(times)
                    else:
                        avg_latency = 0
                    
                    # Extract hostname
                    hostname_match = re.match(r'([^\(]+)', hop_data.strip())
                    hostname = hostname_match.group(1).strip() if hostname_match else None
                    
                    return {
                        'hop': hop_num,
                        'ip': ip_addr,
                        'latency': avg_latency,
                        'hostname': hostname if hostname != ip_addr else None
                    }
            
            return {
                'hop': 0,
                'ip': 'Unknown',
                'latency': 0,
                'hostname': None
            }
            
        except Exception:
            return {
                'hop': 0,
                'ip': 'Unknown',
                'latency': 0,
                'hostname': None
            }
    
    def single_ping(self, target: str, timeout: int = 5) -> Dict[str, Any]:
        """
        Perform a single ping for real-time monitoring
        
        Args:
            target: IP address or hostname to ping
            timeout: Timeout in seconds
            
        Returns:
            Dictionary containing single ping result
        """
        result = self.ping(target, count=1, timeout=timeout)
        
        if result['success'] and result['latencies']:
            return {
                'success': True,
                'latency': result['latencies'][0],
                'packet_loss': result['packet_loss']
            }
        else:
            return {
                'success': False,
                'latency': 0,
                'packet_loss': 100.0,
                'error': result.get('error', 'Ping failed')
            }
