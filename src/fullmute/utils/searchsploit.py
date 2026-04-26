import subprocess
import re
from typing import List, Dict, Optional
from fullmute.utils.logger import setup_logger

logger = setup_logger()



CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')


def validate_cve(cve_id: str) -> bool:
    if not cve_id or not isinstance(cve_id, str):
        return False
    return bool(CVE_PATTERN.match(cve_id))


def search_sploit(cve_id: str) -> List[Dict]:
    
    if not validate_cve(cve_id):
        logger.warning(f"Invalid CVE ID format: {cve_id}")
        return []
    
    try:
        
        
        result = subprocess.run(
            ['searchsploit', '--cve', cve_id],
            capture_output=True,
            text=True,
            timeout=30,  
            shell=False  
        )
        
        if result.returncode != 0:
            
            if 'not found' in result.stderr.lower() or not result.stdout.strip():
                logger.debug(f"No exploits found for {cve_id}")
                return []
            logger.warning(f"searchsploit error for {cve_id}: {result.stderr}")
            return []
        
        
        exploits = parse_searchsploit_output(result.stdout, cve_id)
        return exploits
        
    except subprocess.TimeoutExpired:
        logger.warning(f"searchsploit timeout for {cve_id}")
        return []
    except FileNotFoundError:
        logger.warning("searchsploit command not found")
        return []
    except Exception as e:
        logger.error(f"Error running searchsploit for {cve_id}: {e}")
        return []


def parse_searchsploit_output(output: str, cve_id: str) -> List[Dict]:
    exploits = []
    lines = output.strip().split('\n')
    
    
    in_results = False
    for line in lines:
        line = line.strip()
        
        
        if not line or '---' in line or 'Exploit Title' in line:
            continue
        
        
        if not in_results:
            in_results = True
            continue
        
        
        if '|' in line:
            parts = line.split('|')
            if len(parts) >= 2:
                title = parts[0].strip()
                path = parts[1].strip()
                
                
                exploit_id = extract_exploit_id(path)
                
                
                edb_url = f"https://www.exploit-db.com/exploits/{exploit_id}" if exploit_id else None
                
                exploits.append({
                    'cve_id': cve_id,
                    'title': title,
                    'path': path,
                    'exploit_id': exploit_id,
                    'edb_url': edb_url
                })
    
    return exploits


def extract_exploit_id(path: str) -> Optional[str]:
    """Extract exploit DB ID from path"""
    
    parts = path.split('/')
    if len(parts) >= 3:
        filename = parts[-1]
        
        match = re.match(r'(\d+)', filename)
        if match:
            return match.group(1)
    return None


def search_sploit_batch(cve_list: List[str]) -> Dict[str, List[Dict]]:
    results = {}
    
    for cve_id in cve_list:
        if validate_cve(cve_id):
            exploits = search_sploit(cve_id)
            if exploits:
                results[cve_id] = exploits
                logger.info(f"Found {len(exploits)} exploits for {cve_id}")
            else:
                results[cve_id] = []
        else:
            logger.warning(f"Skipping invalid CVE: {cve_id}")
            results[cve_id] = []
    
    return results
