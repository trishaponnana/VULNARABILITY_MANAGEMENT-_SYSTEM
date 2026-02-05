FINAL_CODE





#!/usr/bin/env python3
"""
Automated Vulnerability Management Dashboard
- Fixed WinRM Mitigation
- Fixed PDF/HTML Report Generation
- Uses docker exec + omp command for OpenVAS
"""

import streamlit as st
import subprocess
import re
import time
import socket
import base64
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

# Try importing winrm
try:
    import winrm
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False


# ============== CONFIGURATION ==============
CONTAINER_NAME = "openvas1"
OPENVAS_WEB_PORT = 9392
OPENVAS_USER = "admin"
OPENVAS_PASS = "admin"

WINDOWS_USER = "srivalli"
WINDOWS_PASS = "valli@8"

SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"


# ============== AUTO IP DETECTION ==============
def check_and_get_ip():
    """Check if Ubuntu has IP, if not run dhclient"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        
        if ip and ip != "127.0.0.1":
            return ip
        else:
            raise Exception("No valid IP")
            
    except Exception:
        try:
            subprocess.run("sudo dhclient -r", shell=True, timeout=30, capture_output=True)
            time.sleep(2)
            subprocess.run("sudo dhclient -v", shell=True, timeout=60, capture_output=True)
            time.sleep(5)
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"


def get_subnet():
    """Get subnet from current IP"""
    ip = check_and_get_ip()
    parts = ip.split('.')
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return subnet, ip


# ============== NETWORK DISCOVERY ==============
def discover_network_devices():
    """Scan network to find all devices"""
    subnet, ubuntu_ip = get_subnet()
    devices = []
    
    try:
        cmd = f"sudo nmap -sn {subnet} -oG -"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        
        lines = result.stdout.split('\n')
        for line in lines:
            if "Host:" in line and "Status: Up" in line:
                match = re.search(r'Host:\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    device_type = "Ubuntu (This Machine)" if ip == ubuntu_ip else "Unknown Device"
                    devices.append({"ip": ip, "type": device_type, "status": "🟢 Online"})
        
        return devices, ubuntu_ip
        
    except Exception as e:
        return [], ubuntu_ip


# ============== DOCKER FUNCTIONS ==============
def check_openvas_container():
    """Check if OpenVAS container is running"""
    try:
        result = subprocess.run(
            f"docker ps --filter name={CONTAINER_NAME} --format '{{{{.Names}}}}'",
            shell=True,
            capture_output=True,
            text=True
        )
        return CONTAINER_NAME in result.stdout
    except Exception:
        return False


def start_openvas_container():
    """Start OpenVAS Docker container"""
    try:
        if check_openvas_container():
            return True, "Already running"
        
        result = subprocess.run(
            f"docker ps -a --filter name={CONTAINER_NAME} --format '{{{{.Names}}}}'",
            shell=True,
            capture_output=True,
            text=True
        )
        
        if CONTAINER_NAME in result.stdout:
            subprocess.run(f"docker start {CONTAINER_NAME}", shell=True, check=True)
            return True, "Started existing container"
        else:
            ubuntu_ip = check_and_get_ip()
            docker_cmd = (
                f"docker run -d "
                f"-p {OPENVAS_WEB_PORT}:443 "
                f"-e PUBLIC_HOSTNAME={ubuntu_ip} "
                f"--name {CONTAINER_NAME} "
                f"mikesplain/openvas"
            )
            subprocess.run(docker_cmd, shell=True, check=True)
            return True, "Created new container"
            
    except Exception as e:
        return False, str(e)


# ============== OMP FUNCTIONS ==============
def run_omp_command(args):
    """Run OMP command inside Docker container"""
    try:
        cmd = f'docker exec {CONTAINER_NAME} omp -u {OPENVAS_USER} -w {OPENVAS_PASS} {args}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def run_omp_xml_command(xml_command):
    """Run OMP command with XML input"""
    try:
        xml_escaped = xml_command.replace('"', '\\"')
        cmd = f'docker exec {CONTAINER_NAME} omp -u {OPENVAS_USER} -w {OPENVAS_PASS} --xml="{xml_escaped}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def test_openvas_connection():
    """Test if OpenVAS is responding"""
    success, stdout, stderr = run_omp_command("-g")
    return success and "Full and fast" in stdout


def create_target(target_ip):
    """Create a target in OpenVAS"""
    target_name = f"Target_{target_ip}_{int(time.time())}"
    
    xml_cmd = f"<create_target><name>{target_name}</name><hosts>{target_ip}</hosts></create_target>"
    success, stdout, stderr = run_omp_xml_command(xml_cmd)
    
    if success and stdout:
        match = re.search(r'id="([a-f0-9-]+)"', stdout)
        if match:
            return True, match.group(1), target_name
        if re.match(r'^[a-f0-9-]+$', stdout):
            return True, stdout, target_name
    
    return False, None, f"Failed: {stderr or stdout}"


def create_task(target_id, target_ip):
    """Create a scan task in OpenVAS"""
    task_name = f"Scan_{target_ip}_{int(time.time())}"
    
    xml_cmd = f"<create_task><name>{task_name}</name><target id='{target_id}'/><config id='{SCAN_CONFIG_ID}'/></create_task>"
    success, stdout, stderr = run_omp_xml_command(xml_cmd)
    
    if success and stdout:
        match = re.search(r'id="([a-f0-9-]+)"', stdout)
        if match:
            return True, match.group(1), task_name
        if re.match(r'^[a-f0-9-]+$', stdout):
            return True, stdout, task_name
    
    return False, None, f"Failed: {stderr or stdout}"


def start_task(task_id):
    """Start a scan task"""
    success, stdout, stderr = run_omp_command(f'-S {task_id}')
    
    if success:
        return True, "Scan started"
    
    xml_cmd = f"<start_task task_id='{task_id}'/>"
    success, stdout, stderr = run_omp_xml_command(xml_cmd)
    
    if success:
        return True, "Scan started"
    
    return False, f"Failed: {stderr or stdout}"


def get_task_status(task_id):
    """Get task status"""
    success, stdout, stderr = run_omp_command(f'-G {task_id}')
    
    if success:
        if "Done" in stdout:
            return "Done", 100, None
        elif "Running" in stdout:
            match = re.search(r'(\d+)%', stdout)
            progress = int(match.group(1)) if match else 50
            return "Running", progress, None
        elif "Requested" in stdout or "Queued" in stdout:
            return "Starting", 5, None
        elif "New" in stdout:
            return "New", 0, None
        else:
            return "Unknown", 0, None
    
    return "Error", 0, stderr


def get_report_id(task_id):
    """Get report ID from task"""
    success, stdout, stderr = run_omp_command(f'-G {task_id}')
    
    if success:
        matches = re.findall(r'([a-f0-9-]{36})', stdout)
        if len(matches) >= 2:
            return True, matches[1]
    
    success, stdout, stderr = run_omp_command('-R')
    if success:
        matches = re.findall(r'([a-f0-9-]{36})', stdout)
        if matches:
            return True, matches[0]
    
    return False, None


# ============== REPORT FUNCTIONS (FIXED - PDF/HTML) ==============
def get_report_formats():
    """Get available report formats"""
    success, stdout, stderr = run_omp_command("--get-report-formats")
    formats = {}
    
    if success:
        for line in stdout.split('\n'):
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    format_id = parts[0]
                    format_name = ' '.join(parts[1:]).lower()
                    formats[format_name] = format_id
    
    return formats


def download_report(report_id, filename):
    """Download report in best available format (PDF or HTML)"""
    
    formats = get_report_formats()
    
    pdf_format_ids = [
        formats.get('pdf', ''),
        'c402cc3e-b531-11e1-9163-406186ea4fc5',
        '5057e5cc-b825-11e4-9d0e-28d24461215b',
    ]
    
    for format_id in pdf_format_ids:
        if not format_id:
            continue
        try:
            success, stdout, stderr = run_omp_command(f'--get-report {report_id} --format {format_id}')
            
            if success and stdout:
                try:
                    pdf_content = base64.b64decode(stdout)
                    if b'%PDF' in pdf_content[:20]:
                        pdf_file = filename.replace('.xml', '.pdf').replace('.html', '.pdf')
                        if not pdf_file.endswith('.pdf'):
                            pdf_file += '.pdf'
                        Path(pdf_file).write_bytes(pdf_content)
                        return True, pdf_file
                except:
                    pass
                
                if b'%PDF' in stdout.encode()[:20]:
                    pdf_file = filename.replace('.xml', '.pdf').replace('.html', '.pdf')
                    if not pdf_file.endswith('.pdf'):
                        pdf_file += '.pdf'
                    Path(pdf_file).write_bytes(stdout.encode())
                    return True, pdf_file
        except:
            continue
    
    success, stdout, stderr = run_omp_command(f'--get-report {report_id}')
    
    if success and stdout:
        xml_file = filename.replace('.pdf', '.xml').replace('.html', '.xml')
        if not xml_file.endswith('.xml'):
            xml_file += '.xml'
        Path(xml_file).write_text(stdout)
        
        html_file = xml_file.replace('.xml', '.html')
        if create_html_report(xml_file, html_file):
            return True, html_file
        
        return True, xml_file
    
    return False, None


def create_html_report(xml_file, html_file):
    """Create beautiful HTML report from XML"""
    try:
        content = Path(xml_file).read_text()
        
        vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        vulns = []
        
        try:
            root = ET.fromstring(content)
            for result in root.findall(".//result"):
                sev_elem = result.find(".//severity")
                name_elem = result.find(".//name")
                port_elem = result.find(".//port")
                desc_elem = result.find(".//description")
                host_elem = result.find(".//host")
                
                if sev_elem is not None and sev_elem.text:
                    try:
                        sev = float(sev_elem.text)
                        name = name_elem.text if name_elem is not None else "Unknown"
                        port = port_elem.text if port_elem is not None else "N/A"
                        desc = desc_elem.text[:300] if desc_elem is not None and desc_elem.text else "N/A"
                        host = host_elem.text if host_elem is not None else "N/A"
                        
                        if sev >= 9.0:
                            level = "Critical"
                        elif sev >= 7.0:
                            level = "High"
                        elif sev >= 4.0:
                            level = "Medium"
                        elif sev > 0:
                            level = "Low"
                        else:
                            continue
                        
                        vuln_counts[level] += 1
                        vulns.append({
                            "level": level,
                            "score": sev,
                            "name": name,
                            "port": port,
                            "desc": desc,
                            "host": host
                        })
                    except:
                        pass
        except ET.ParseError:
            pass
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report</title>
    <meta charset="UTF-8">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
        }}
        .container {{ 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 15px; 
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 3px solid #4CAF50;
        }}
        h1 {{ 
            color: #1a1a2e; 
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .timestamp {{
            color: #666;
            font-size: 1.1em;
        }}
        .summary {{ 
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px; 
            margin: 30px 0;
        }}
        .card {{ 
            padding: 25px; 
            border-radius: 12px; 
            color: white; 
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            transition: transform 0.3s;
        }}
        .card:hover {{
            transform: translateY(-5px);
        }}
        .critical {{ background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }}
        .high {{ background: linear-gradient(135deg, #fd7e14 0%, #e8590c 100%); }}
        .medium {{ background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%); color: #333; }}
        .low {{ background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%); }}
        .count {{ 
            font-size: 48px; 
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        .label {{ 
            font-size: 18px;
            margin-top: 5px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        h2 {{
            color: #1a1a2e;
            margin: 30px 0 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }}
        table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        th {{ 
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            color: white; 
            padding: 15px; 
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        td {{ 
            padding: 12px 15px; 
            border-bottom: 1px solid #eee;
            vertical-align: top;
        }}
        tr:hover {{ background: #f8f9fa; }}
        .sev-critical {{ 
            color: #dc3545; 
            font-weight: bold;
            background: #fff5f5;
            padding: 5px 10px;
            border-radius: 5px;
        }}
        .sev-high {{ 
            color: #fd7e14; 
            font-weight: bold;
            background: #fff8f0;
            padding: 5px 10px;
            border-radius: 5px;
        }}
        .sev-medium {{ 
            color: #856404;
            background: #fff9e6;
            padding: 5px 10px;
            border-radius: 5px;
        }}
        .sev-low {{ 
            color: #28a745;
            background: #f0fff4;
            padding: 5px 10px;
            border-radius: 5px;
        }}
        .vuln-name {{
            font-weight: 600;
            color: #1a1a2e;
        }}
        .port {{
            font-family: monospace;
            background: #e9ecef;
            padding: 3px 8px;
            border-radius: 4px;
        }}
        .desc {{
            color: #666;
            font-size: 0.9em;
            max-width: 400px;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 2px solid #eee;
            color: #666;
        }}
        .no-vulns {{
            text-align: center;
            padding: 50px;
            color: #28a745;
            font-size: 1.5em;
        }}
        @media print {{
            body {{ background: white; }}
            .container {{ box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Vulnerability Scan Report</h1>
            <p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="summary">
            <div class="card critical">
                <div class="count">{vuln_counts['Critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="card high">
                <div class="count">{vuln_counts['High']}</div>
                <div class="label">High</div>
            </div>
            <div class="card medium">
                <div class="count">{vuln_counts['Medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="card low">
                <div class="count">{vuln_counts['Low']}</div>
                <div class="label">Low</div>
            </div>
        </div>
        
        <h2>📋 Vulnerability Details</h2>
"""
        
        if vulns:
            html += """
        <table>
            <tr>
                <th>Severity</th>
                <th>Score</th>
                <th>Vulnerability</th>
                <th>Port</th>
                <th>Description</th>
            </tr>
"""
            
            for v in sorted(vulns, key=lambda x: x['score'], reverse=True):
                sev_class = f"sev-{v['level'].lower()}"
                html += f"""
            <tr>
                <td><span class="{sev_class}">{v['level']}</span></td>
                <td><strong>{v['score']}</strong></td>
                <td class="vuln-name">{v['name']}</td>
                <td><span class="port">{v['port']}</span></td>
                <td class="desc">{v['desc'][:200]}...</td>
            </tr>
"""
            
            html += "        </table>"
        else:
            html += """
        <div class="no-vulns">
            ✅ No vulnerabilities found!
        </div>
"""
        
        html += f"""
        
        <div class="footer">
            <p>Generated by Automated Vulnerability Management Dashboard</p>
            <p>Total Vulnerabilities: {sum(vuln_counts.values())}</p>
        </div>
    </div>
</body>
</html>
"""
        
        Path(html_file).write_text(html)
        return True
        
    except Exception as e:
        return False


def parse_openvas_report(filename):
    """Parse vulnerabilities from OpenVAS report"""
    vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    vuln_list = []
    
    try:
        if not Path(filename).exists():
            return vuln_counts, vuln_list
        
        content = Path(filename).read_text()
        
        try:
            root = ET.fromstring(content)
            
            for result in root.findall(".//result"):
                sev_elem = result.find(".//severity")
                name_elem = result.find(".//name")
                port_elem = result.find(".//port")
                
                if sev_elem is not None and sev_elem.text:
                    try:
                        severity = float(sev_elem.text)
                        name = name_elem.text if name_elem is not None else "Unknown"
                        port = port_elem.text if port_elem is not None else "Unknown"
                        
                        if severity >= 9.0:
                            vuln_counts["Critical"] += 1
                            vuln_list.append({"severity": "Critical", "name": name, "port": port})
                        elif severity >= 7.0:
                            vuln_counts["High"] += 1
                            vuln_list.append({"severity": "High", "name": name, "port": port})
                        elif severity >= 4.0:
                            vuln_counts["Medium"] += 1
                            vuln_list.append({"severity": "Medium", "name": name, "port": port})
                        elif severity > 0:
                            vuln_counts["Low"] += 1
                            vuln_list.append({"severity": "Low", "name": name, "port": port})
                    except ValueError:
                        pass
        except ET.ParseError:
            pass
        
    except Exception:
        pass
    
    return vuln_counts, vuln_list


def get_ports_from_report(filename):
    """Extract ports from OpenVAS report"""
    ports = []
    try:
        if Path(filename).exists():
            content = Path(filename).read_text()
            port_matches = re.findall(r'(\d+)/(tcp|udp)', content)
            for port, proto in port_matches:
                port_num = int(port)
                if port_num not in ports and port_num < 65536:
                    ports.append(port_num)
    except Exception:
        pass
    return sorted(ports)


# ============== NMAP FUNCTIONS ==============
def run_nmap_asset_scan(target_ip):
    """Run Nmap asset inventory scan"""
    try:
        cmd = f"sudo nmap -sV -O -sC {target_ip} -oN asset_inventory.txt"
        subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        if Path("asset_inventory.txt").exists():
            return True, Path("asset_inventory.txt").read_text()
        return False, "File not created"
        
    except subprocess.TimeoutExpired:
        return False, "Scan timed out"
    except Exception as e:
        return False, str(e)


def run_nmap_vuln_scan(target_ip):
    """Run Nmap vulnerability scan"""
    try:
        cmd = f"sudo nmap -sV --script vulners {target_ip} -oN vuln_report.txt"
        subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        if Path("vuln_report.txt").exists():
            return True, Path("vuln_report.txt").read_text()
        return False, "File not created"
        
    except subprocess.TimeoutExpired:
        return False, "Scan timed out"
    except Exception as e:
        return False, str(e)


def run_nmap_eternalblue_scan(target_ip, ports):
    """Run Nmap EternalBlue scan"""
    try:
        if not ports:
            return False, "No ports to scan"
        
        ports_str = ",".join(map(str, ports))
        cmd = f"sudo nmap -p {ports_str} --script smb-vuln-ms17-010 {target_ip} -oN eternalblue_scan.txt"
        subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        if Path("eternalblue_scan.txt").exists():
            return True, Path("eternalblue_scan.txt").read_text()
        return False, "File not created"
        
    except subprocess.TimeoutExpired:
        return False, "Scan timed out"
    except Exception as e:
        return False, str(e)


def parse_open_ports(filename):
    """Parse open ports from Nmap output"""
    ports = []
    try:
        if Path(filename).exists():
            content = Path(filename).read_text()
            pattern = r"^(\d+)/tcp\s+open"
            matches = re.findall(pattern, content, re.MULTILINE)
            ports = [int(p) for p in matches]
    except Exception:
        pass
    return ports


def parse_vulnerable_ports(filename):
    """Parse ports with vulnerabilities"""
    vulnerable_ports = []
    try:
        if not Path(filename).exists():
            return []
        
        content = Path(filename).read_text()
        lines = content.split('\n')
        current_port = None
        
        for line in lines:
            port_match = re.match(r"^(\d+)/tcp\s+open", line)
            if port_match:
                current_port = int(port_match.group(1))
            
            if current_port and ('CVE' in line.upper() or 'VULNERS' in line.upper() or 'VULNERABLE' in line.upper()):
                if current_port not in vulnerable_ports:
                    vulnerable_ports.append(current_port)
        
        return sorted(vulnerable_ports)
        
    except Exception:
        return []


# ============== WINRM MITIGATION (FIXED) ==============
def test_winrm_connection(target_ip):
    """Test WinRM connection to Windows"""
    if not WINRM_AVAILABLE:
        return False, "WinRM module not installed"
    
    try:
        session = winrm.Session(
            target=f"http://{target_ip}:5985/wsman",
            auth=(WINDOWS_USER, WINDOWS_PASS),
            transport='ntlm',
            server_cert_validation='ignore'
        )
        
        result = session.run_cmd('hostname')
        if result.status_code == 0:
            hostname = result.std_out.decode().strip()
            return True, f"Connected to {hostname}"
        else:
            return False, "Connection failed"
            
    except Exception as e:
        return False, str(e)


def mitigate_vulnerabilities(target_ip, ports):
    """Block vulnerable ports via WinRM - FIXED VERSION"""
    if not WINRM_AVAILABLE:
        return False, [], ["WinRM module not installed. Run: pip3 install pywinrm"]
    
    if not ports:
        return False, [], ["No ports to block"]
    
    blocked = []
    failed = []
    
    try:
        session = winrm.Session(
            target=f"http://{target_ip}:5985/wsman",
            auth=(WINDOWS_USER, WINDOWS_PASS),
            transport='ntlm',
            server_cert_validation='ignore'
        )
        
        test_result = session.run_cmd('echo Connected')
        if test_result.status_code != 0:
            return False, [], ["Cannot connect to Windows. Enable WinRM first."]
        
        for port in ports:
            try:
                rule_name = f"Block_Vuln_Port_{port}"
                
                cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block protocol=TCP localport={port}'
                result_in = session.run_cmd(cmd_in)
                
                cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block protocol=TCP localport={port}'
                result_out = session.run_cmd(cmd_out)
                
                if result_in.status_code == 0 or result_out.status_code == 0:
                    blocked.append(port)
                else:
                    error = result_in.std_err.decode() if result_in.std_err else "Unknown error"
                    failed.append(f"Port {port}: {error}")
                    
            except Exception as e:
                failed.append(f"Port {port}: {str(e)}")
        
        return len(blocked) > 0, blocked, failed
        
    except Exception as e:
        return False, [], [f"Connection error: {str(e)}. Make sure WinRM is enabled on Windows."]


def remove_firewall_rules(target_ip, ports):
    """Remove firewall rules (for testing)"""
    if not WINRM_AVAILABLE:
        return False, []
    
    removed = []
    
    try:
        session = winrm.Session(
            target=f"http://{target_ip}:5985/wsman",
            auth=(WINDOWS_USER, WINDOWS_PASS),
            transport='ntlm',
            server_cert_validation='ignore'
        )
        
        for port in ports:
            try:
                cmd_in = f'netsh advfirewall firewall delete rule name="Block_Vuln_Port_{port}_IN"'
                cmd_out = f'netsh advfirewall firewall delete rule name="Block_Vuln_Port_{port}_OUT"'
                
                session.run_cmd(cmd_in)
                session.run_cmd(cmd_out)
                removed.append(port)
            except:
                pass
        
        return True, removed
        
    except Exception:
        return False, []


# ============== COMPARISON ==============
def compare_reports(before_file, after_file):
    """Compare two reports"""
    before_vulns, _ = parse_openvas_report(before_file)
    after_vulns, _ = parse_openvas_report(after_file)
    
    comparison = {}
    for severity in before_vulns:
        before_count = before_vulns[severity]
        after_count = after_vulns[severity]
        diff = before_count - after_count
        comparison[severity] = {
            "before": before_count,
            "after": after_count,
            "fixed": diff
        }
    
    return comparison


# ============== MAIN UI ==============
def main():
    st.set_page_config(
        page_title="Vulnerability Dashboard",
        page_icon="🛡️",
        layout="wide"
    )
    
    st.title("🛡️ Automated Vulnerability Management Dashboard")
    
    ubuntu_ip = check_and_get_ip()
    
    defaults = {
        "devices": [],
        "target_ip": "",
        "nmap_done": False,
        "vulnerable_ports": [],
        "target_id": None,
        "task_id": None,
        "scan_complete": False,
        "before_report": None,
        "before_report_xml": None,
        "mitigation_done": False,
        "after_report": None
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
    
    # ========== SIDEBAR ==========
    with st.sidebar:
        st.header("⚙️ System Info")
        st.success(f"🖥️ Ubuntu: {ubuntu_ip}")
        st.info(f"🌐 OpenVAS: Port {OPENVAS_WEB_PORT}")
        
        st.divider()
        
        st.subheader("🐳 Docker Controls")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("▶️ Start"):
                success, msg = start_openvas_container()
                if success:
                    st.success(f"✅ {msg}")
                else:
                    st.error(f"❌ {msg}")
        
        with col2:
            if st.button("⏹️ Stop"):
                subprocess.run(f"docker stop {CONTAINER_NAME}", shell=True, capture_output=True)
                st.success("✅ Stopped")
        
        if st.button("🔄 Test OpenVAS", use_container_width=True):
            if check_openvas_container():
                if test_openvas_connection():
                    st.success("✅ OpenVAS Ready!")
                else:
                    st.warning("⏳ Wait 2-3 min...")
            else:
                st.error("❌ Not running")
        
        st.divider()
        
        st.subheader("🔐 Test WinRM")
        test_ip = st.text_input("Windows IP", placeholder="Enter Windows VM IP")
        if st.button("🔌 Test Connection"):
            if test_ip:
                success, msg = test_winrm_connection(test_ip)
                if success:
                    st.success(f"✅ {msg}")
                else:
                    st.error(f"❌ {msg}")
                    st.info("Run on Windows:\nwinrm quickconfig -force")
        
        st.divider()
        
        st.subheader("📊 Status")
        st.write(f"🎯 Target: {st.session_state.target_ip or 'Not set'}")
        st.write(f"🔍 Nmap: {'✅' if st.session_state.nmap_done else '❌'}")
        st.write(f"🛡️ Scan: {'✅' if st.session_state.scan_complete else '❌'}")
        st.write(f"🛑 Fixed: {'✅' if st.session_state.mitigation_done else '❌'}")
    
    # ========== MAIN CONTENT ==========
    
    # Step 1: Network Discovery
    st.header("📡 Step 1: Discover Network")
    
    if st.button("🔍 SCAN NETWORK", type="primary"):
        with st.spinner("Scanning..."):
            devices, _ = discover_network_devices()
            st.session_state.devices = devices
            st.success(f"✅ Found {len(devices)} devices")
    
    if st.session_state.devices:
        for device in st.session_state.devices:
            st.write(f"📍 **{device['ip']}** - {device['status']} - {device['type']}")
    
    st.divider()
    
    # Step 2: Add Asset & Nmap
    st.header("➕ Step 2: Add Asset & Nmap Scans")
    
    target_ip = st.text_input("Enter Target IP", placeholder="e.g., 192.168.1.100")
    
    if st.button("➕ ADD & SCAN", type="primary"):
        if not target_ip:
            st.error("❌ Enter IP!")
        else:
            st.session_state.target_ip = target_ip
            st.session_state.nmap_done = False
            st.session_state.scan_complete = False
            st.session_state.mitigation_done = False
            
            with st.status("🔄 Running Nmap...", expanded=True):
                
                st.write("### Scan 1: Asset Inventory")
                success, content = run_nmap_asset_scan(target_ip)
                if success:
                    st.success("✅ asset_inventory.txt")
                    with st.expander("View"):
                        st.code(content)
                
                st.write("### Scan 2: Vulnerabilities")
                success, content = run_nmap_vuln_scan(target_ip)
                if success:
                    st.success("✅ vuln_report.txt")
                    with st.expander("View"):
                        st.code(content)
                
                st.write("### Detecting Ports...")
                all_ports = parse_open_ports("asset_inventory.txt")
                vuln_ports = parse_vulnerable_ports("vuln_report.txt")
                combined = sorted(list(set(all_ports + vuln_ports)))
                st.session_state.vulnerable_ports = combined
                st.success(f"✅ Ports: {combined}")
                
                if combined:
                    st.write("### Scan 3: EternalBlue")
                    success, content = run_nmap_eternalblue_scan(target_ip, combined)
                    if success:
                        st.success("✅ eternalblue_scan.txt")
                        with st.expander("View"):
                            st.code(content)
                
                st.session_state.nmap_done = True
    
    st.divider()
    
    # Step 3: Download Nmap Reports
    if st.session_state.nmap_done:
        st.header("📥 Step 3: Download Nmap Reports")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if Path("asset_inventory.txt").exists():
                st.download_button(
                    "📥 asset_inventory.txt",
                    Path("asset_inventory.txt").read_bytes(),
                    "asset_inventory.txt",
                    mime="text/plain"
                )
        
        with col2:
            if Path("vuln_report.txt").exists():
                st.download_button(
                    "📥 vuln_report.txt",
                    Path("vuln_report.txt").read_bytes(),
                    "vuln_report.txt",
                    mime="text/plain"
                )
        
        with col3:
            if Path("eternalblue_scan.txt").exists():
                st.download_button(
                    "📥 eternalblue_scan.txt",
                    Path("eternalblue_scan.txt").read_bytes(),
                    "eternalblue_scan.txt",
                    mime="text/plain"
                )
        
        st.divider()
    
    # Step 4: OpenVAS Scan
    if st.session_state.nmap_done:
        st.header("🛡️ Step 4: OpenVAS Scan")
        
        if not check_openvas_container():
            st.warning("⚠️ Start OpenVAS first (sidebar)")
        elif not test_openvas_connection():
            st.warning("⏳ OpenVAS initializing... wait 2-3 minutes")
        else:
            st.success("✅ OpenVAS Ready")
            
            if st.button("🚀 START OPENVAS SCAN", type="primary"):
                target = st.session_state.target_ip
                
                with st.status("🔄 OpenVAS Scanning...", expanded=True):
                    
                    st.write("### Creating Target...")
                    success, target_id, msg = create_target(target)
                    if not success:
                        st.error(f"❌ {msg}")
                        st.stop()
                    st.success(f"✅ Target: {target_id}")
                    st.session_state.target_id = target_id
                    
                    st.write("### Creating Task...")
                    success, task_id, msg = create_task(target_id, target)
                    if not success:
                        st.error(f"❌ {msg}")
                        st.stop()
                    st.success(f"✅ Task: {task_id}")
                    st.session_state.task_id = task_id
                    
                    st.write("### Starting Scan...")
                    success, msg = start_task(task_id)
                    if not success:
                        st.error(f"❌ {msg}")
                        st.stop()
                    st.success("✅ Scan started!")
                    
                    st.write("### Scanning...")
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    
                    while True:
                        status, progress, error = get_task_status(task_id)
                        progress_bar.progress(min(progress, 100))
                        status_text.write(f"Status: {status} - {progress}%")
                        
                        if status == "Done":
                            break
                        elif status == "Error":
                            st.error(f"❌ Scan error: {error}")
                            st.stop()
                        
                        time.sleep(15)
                    
                    st.write("### Downloading Report...")
                    success, report_id = get_report_id(task_id)
                    
                    if success:
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        filename = f"OpenVAS_Report_{timestamp}"
                        success, report_file = download_report(report_id, filename)
                        
                        if success:
                            st.session_state.before_report = report_file
                            
                            xml_file = report_file.replace('.html', '.xml').replace('.pdf', '.xml')
                            if Path(xml_file).exists():
                                st.session_state.before_report_xml = xml_file
                            
                            st.success(f"✅ Report: {report_file}")
                            
                            xml_for_parse = st.session_state.before_report_xml or report_file
                            vuln_counts, vuln_list = parse_openvas_report(xml_for_parse)
                            
                            col1, col2, col3, col4 = st.columns(4)
                            col1.metric("🔴 Critical", vuln_counts["Critical"])
                            col2.metric("🟠 High", vuln_counts["High"])
                            col3.metric("🟡 Medium", vuln_counts["Medium"])
                            col4.metric("🟢 Low", vuln_counts["Low"])
                            
                            report_ports = get_ports_from_report(xml_for_parse)
                            combined = sorted(list(set(st.session_state.vulnerable_ports + report_ports)))
                            st.session_state.vulnerable_ports = combined
                    
                    st.session_state.scan_complete = True
    
    st.divider()
    
    # Step 5: Download OpenVAS Report
    if st.session_state.scan_complete and st.session_state.before_report:
        st.header("📥 Step 5: Download OpenVAS Report")
        
        report = st.session_state.before_report
        if Path(report).exists():
            mime_type = "text/html" if report.endswith('.html') else "application/pdf" if report.endswith('.pdf') else "application/xml"
            st.download_button(
                f"📥 Download {Path(report).name}",
                Path(report).read_bytes(),
                Path(report).name,
                mime=mime_type
            )
            
            if report.endswith('.html'):
                st.info("💡 Open the HTML file in your browser for a beautiful report!")
        
        st.divider()
    
    # Step 6: Mitigation
    if st.session_state.nmap_done:
        st.header("🛑 Step 6: Mitigate Vulnerabilities")
        
        ports = st.session_state.vulnerable_ports
        
        if ports:
            st.warning(f"⚠️ Ports to block: **{ports}**")
            
            if not WINRM_AVAILABLE:
                st.error("❌ Install WinRM: pip3 install pywinrm")
            else:
                target = st.session_state.target_ip
                
                col1, col2 = st.columns(2)
                
                with col1:
                    if st.button("🛑 BLOCK PORTS", type="primary", use_container_width=True):
                        with st.status("🔄 Blocking ports...", expanded=True):
                            
                            st.write(f"Connecting to {target}...")
                            success, blocked, failed = mitigate_vulnerabilities(target, ports)
                            
                            if blocked:
                                st.success(f"✅ Blocked: {blocked}")
                                for port in blocked:
                                    st.write(f"  ✅ Port {port} blocked")
                            
                            if failed:
                                st.warning("⚠️ Some ports failed:")
                                for f in failed:
                                    st.write(f"  ❌ {f}")
                            
                            if success:
                                st.session_state.mitigation_done = True
                                st.balloons()
                
                with col2:
                    if st.button("🔓 UNBLOCK PORTS", use_container_width=True):
                        success, removed = remove_firewall_rules(target, ports)
                        if removed:
                            st.success(f"✅ Removed rules for: {removed}")
                            st.session_state.mitigation_done = False
        else:
            st.info("ℹ️ No ports found")
        
        st.divider()
    
    # Step 7: Rescan
    if st.session_state.mitigation_done:
        st.header("🔄 Step 7: Rescan & Compare")
        
        if st.button("🔍 RESCAN & COMPARE", type="primary"):
            target = st.session_state.target_ip
            
            with st.status("🔄 Rescanning...", expanded=True):
                
                st.write("### Nmap Rescan...")
                success, content = run_nmap_vuln_scan(target)
                if success:
                    Path("vuln_report_after.txt").write_text(content)
                    st.success("✅ Nmap done")
                
                if check_openvas_container() and test_openvas_connection():
                    st.write("### OpenVAS Rescan...")
                    
                    success, target_id, _ = create_target(target)
                    if success:
                        success, task_id, _ = create_task(target_id, target)
                        if success:
                            start_task(task_id)
                            
                            progress_bar = st.progress(0)
                            while True:
                                status, progress, _ = get_task_status(task_id)
                                progress_bar.progress(min(progress, 100))
                                st.write(f"Progress: {progress}%")
                                if status == "Done":
                                    break
                                time.sleep(15)
                            
                            success, report_id = get_report_id(task_id)
                            if success:
                                filename = f"OpenVAS_After_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                                success, report_file = download_report(report_id, filename)
                                if success:
                                    st.session_state.after_report = report_file
                                    st.success(f"✅ After report: {report_file}")
            
            st.subheader("📊 Comparison Results")
            
            before_ports = st.session_state.vulnerable_ports
            after_ports = []
            if Path("vuln_report_after.txt").exists():
                after_ports = parse_open_ports("vuln_report_after.txt")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.write("**Before Mitigation:**")
                st.write(f"{len(before_ports)} ports")
                st.write(before_ports)
            
            with col2:
                st.write("**After Mitigation:**")
                st.write(f"{len(after_ports)} ports")
                st.write(after_ports)
            
            with col3:
                blocked = set(before_ports) - set(after_ports)
                st.write("**Blocked:**")
                st.write(f"{len(blocked)} ports")
                if blocked:
                    st.success(f"✅ {list(blocked)}")
            
            if st.session_state.before_report_xml and st.session_state.after_report:
                after_xml = st.session_state.after_report.replace('.html', '.xml').replace('.pdf', '.xml')
                if Path(st.session_state.before_report_xml).exists() and Path(after_xml).exists():
                    comparison = compare_reports(st.session_state.before_report_xml, after_xml)
                    
                    st.subheader("📈 Vulnerability Comparison")
                    
                    cols = st.columns(4)
                    for i, (severity, data) in enumerate(comparison.items()):
                        with cols[i]:
                            st.metric(
                                severity,
                                f"{data['after']}",
                                f"{-data['fixed']} fixed" if data['fixed'] > 0 else None,
                                delta_color="inverse"
                            )
    
    # Footer
    st.divider()
    openvas_url = f"https://{ubuntu_ip}:{OPENVAS_WEB_PORT}"
    st.caption(f"🖥️ Ubuntu: {ubuntu_ip} | 🌐 [OpenVAS Web UI]({openvas_url}) | 👤 Windows User: {WINDOWS_USER}")


if __name__ == "__main__":
    main()
