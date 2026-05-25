import subprocess
import re
import json
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
    if not path:
        return None
    # common patterns include .../exploits/12345.py or .../exploits/12345/...
    m = re.search(r"(\d{3,7})", path)
    if m:
        return m.group(1)
    return None


def search_sploit(cve_id: str) -> List[Dict]:
    """Search for exploits for a single CVE using searchsploit.
    Try JSON output first (-j), fall back to plain text parsing.
    """
    if not validate_cve(cve_id):
        logger.warning(f"Invalid CVE ID format: {cve_id}")
        return []

    # Try JSON output first (-j), then plain text
    attempts = [(['searchsploit', '-j', '--cve', cve_id]), (['searchsploit', '--cve', cve_id])]
    for args in attempts:
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False
            )
        except FileNotFoundError:
            logger.warning("searchsploit command not found")
            return []
        except subprocess.TimeoutExpired:
            logger.warning(f"searchsploit timeout for {cve_id}")
            return []
        except Exception as e:
            logger.debug(f"searchsploit invocation error for {cve_id}: {e}")
            continue

        out = (result.stdout or '').strip()
        if not out:
            # nothing to parse, try next invocation
            continue

        # If JSON output, parse it
        try:
            parsed = json.loads(out)
            entries = parsed.get('RESULTS_EXPLOIT') or parsed.get('RESULTS') or []
            exploits = []
            for e in entries:
                title = e.get('Title') or e.get('title') or ''
                path = e.get('Path') or e.get('Path') or e.get('path') or ''
                exploit_id = e.get('EDB-ID') or e.get('EDB ID') or extract_exploit_id(path)
                edb_url = f"https://www.exploit-db.com/exploits/{exploit_id}" if exploit_id else None
                exploits.append({
                    'cve_id': cve_id,
                    'title': title,
                    'path': path,
                    'exploit_id': exploit_id,
                    'edb_url': edb_url
                })
            if exploits:
                return exploits
        except Exception:
            # Fallback to text parsing of standard searchsploit output
            try:
                exploits = parse_searchsploit_output(out, cve_id)
                return exploits
            except Exception as e:
                logger.debug(f"Failed to parse searchsploit output for {cve_id}: {e}")
                return []

    # No exploits found
    logger.debug(f"No exploits found for {cve_id}")
    return []


def search_sploit_batch(cve_list: List[str]) -> Dict[str, List[Dict]]:
    results = {}

    for cve_id in cve_list:
        if validate_cve(cve_id):
            try:
                exploits = search_sploit(cve_id)
            except Exception as e:
                logger.debug(f"Error searching exploits for {cve_id}: {e}")
                exploits = []
            results[cve_id] = exploits or []
            if exploits:
                logger.info(f"Found {len(exploits)} exploits for {cve_id}")
        else:
            logger.warning(f"Skipping invalid CVE: {cve_id}")
            results[cve_id] = []

    return results
