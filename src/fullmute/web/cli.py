
"""
FullMute Web Setup and Launch Script
Quick setup utility for FullMute Web Interface
"""
import sys
import os
import click
import secrets
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent / 'src'))

from fullmute.web.database import init_web_db, create_user, generate_api_key, get_user_by_id
from fullmute.web.config import config


def print_banner():
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║   FullMute Web Interface Setup                        ║
    ║   Advanced Web Security Scanner                       ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """)


@click.group()
def cli():
    pass


@cli.command()
@click.option('--username', '-u', default='admin', help='Admin username')
@click.option('--role', '-r', default='admin', type=click.Choice(['admin', 'viewer']), help='User role')
def init(username, role):
    print_banner()
    
    print("[*] Initializing database...")
    init_web_db()
    print("[+] Database initialized successfully")
    
    
    print(f"\n[*] Creating {role} user '{username}'...")
    
    api_key = generate_api_key()
    user_id = create_user(username=username, api_key=api_key, role=role)
    
    if user_id:
        print("[+] User created successfully!\n")
        print("=" * 60)
        print(" IMPORTANT: Save this API key!")
        print("=" * 60)
        print(f"\n  Username: {username}")
        print(f"  Role: {role}")
        print(f"  API Key: {api_key}")
        print("\n" + "=" * 60)
        print(" This key will NOT be shown again!")
        print("=" * 60)
        print("\nYou can now start the web server with:")
        print("  fullmute web start\n")
    else:
        print(f"[-] User '{username}' already exists!")
        print("    Use 'fullmute web list-users' to see existing users\n")


@cli.command()
@click.option('--username', '-u', required=True, help='Username for new API key')
def regenerate_key(username):
    from fullmute.web.database import list_users, regenerate_api_key
    
    users = list_users()
    user = next((u for u in users if u['username'] == username), None)
    
    if not user:
        print(f"[-] User '{username}' not found!")
        return
    
    new_key = regenerate_api_key(user['id'])
    
    if new_key:
        print("[+] API key regenerated successfully!\n")
        print("=" * 60)
        print(f"  Username: {username}")
        print(f"  New API Key: {new_key}")
        print("=" * 60)
        print("\n⚠️  The old API key is now invalid!\n")
    else:
        print("[-] Failed to regenerate API key\n")


@cli.command()
def list_users():
    from fullmute.web.database import list_users
    
    users = list_users()
    
    if not users:
        print("No users found. Run 'fullmute web init' to create admin user.\n")
        return
    
    print("\n" + "=" * 60)
    print(" FullMute Web Users")
    print("=" * 60)
    print(f"{'Username':<20} {'Role':<10} {'API Key Prefix':<20} {'Status':<10}")
    print("-" * 60)
    
    for user in users:
        status = "Active" if user['is_active'] else "Inactive"
        print(f"{user['username']:<20} {user['role']:<10} {user['api_key_prefix']:<20} {status:<10}")
    
    print("=" * 60 + "\n")


@cli.command()
@click.option('--host', '-h', default=None, help='Host to bind to')
@click.option('--port', '-p', default=None, type=int, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def start(host, port, debug):
    """Start the FullMute Web server"""
    import uvicorn
    
    
    if host:
        config.host = host
    if port:
        config.port = port
    if debug:
        config.debug = debug
    
    print_banner()
    
    
    db_path = Path(config.database_path)
    if not db_path.exists():
        print("[*] Database not found. Initializing...")
        init_web_db()
        print("[+] Database initialized")
        
        
        from fullmute.web.database import list_users
        if not list_users():
            print("\n[*] No users found. Creating default admin user...")
            api_key = generate_api_key()
            create_user(username='admin', api_key=api_key, role='admin')
            print("\n" + "=" * 60)
            print(" DEFAULT ADMIN USER CREATED")
            print("=" * 60)
            print(f"\n  Username: admin")
            print(f"  API Key: {api_key}")
            print("\n" + "=" * 60 + "\n")
    
    print(f"[*] Starting web server on http://{config.host}:{config.port}")
    print("[*] Press Ctrl+C to stop\n")
    
    try:
        uvicorn.run(
            "fullmute.web.app:app",
            host=config.host,
            port=config.port,
            reload=config.debug,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n\n[!] Server stopped by user")
        sys.exit(0)


@cli.command()
def status():
    from pathlib import Path
    
    print_banner()
    
    print("\n" + "=" * 60)
    print(" FullMute Web Status")
    print("=" * 60)
    
    
    db_path = Path(config.database_path)
    scanner_db = Path(config.scanner_database)
    
    print(f"\n📊 Configuration:")
    print(f"   Host: {config.host}")
    print(f"   Port: {config.port}")
    print(f"   Debug: {config.debug}")
    
    print(f"\n💾 Database:")
    print(f"   Web DB: {db_path} [{'✓' if db_path.exists() else '✗'}]")
    print(f"   Scanner DB: {scanner_db} [{'✓' if scanner_db.exists() else '✗'}]")
    
    
    from fullmute.web.database import list_users
    users = list_users()
    print(f"\n👥 Users: {len(users)}")
    
    if users:
        admins = sum(1 for u in users if u['role'] == 'admin')
        viewers = sum(1 for u in users if u['role'] == 'viewer')
        print(f"   Admins: {admins}")
        print(f"   Viewers: {viewers}")
    
    
    from fullmute.web.database import get_scan_configs
    configs = get_scan_configs()
    scheduled = sum(1 for c in configs if c.get('schedule_type'))
    print(f"\n📅 Scheduled Scans: {scheduled}")
    
    print("\n" + "=" * 60 + "\n")


@cli.command()
@click.option('--username', '-u', required=True, help='Username to delete')
@click.confirmation_option(prompt='Are you sure you want to delete this user?')
def delete_user(username):
    from fullmute.web.database import get_db_connection
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        
        if cursor.rowcount > 0:
            print(f"[+] User '{username}' deleted successfully\n")
        else:
            print(f"[-] User '{username}' not found\n")


@cli.command()
def reset():
    from pathlib import Path
    
    db_path = Path(config.database_path)
    
    if not db_path.exists():
        print("[-] Database does not exist\n")
        return
    
    click.confirm("⚠️  WARNING: This will DELETE ALL DATA! Are you sure?", abort=True)
    
    db_path.unlink()
    print("[+] Database deleted\n")
    print("Run 'fullmute web init' to create a new database\n")


def main():
    cli()


if __name__ == "__main__":
    main()
