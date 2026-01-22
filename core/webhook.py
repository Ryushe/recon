import json
import requests
import urllib.parse
from datetime import datetime


def send_discord_notification(webhook_url, title, description, color=0x00ff00, fields=None, footer_text=None):
    """
    Send a notification to Discord webhook
    
    Args:
        webhook_url (str): Discord webhook URL
        title (str): Embed title
        description (str): Embed description
        color (int): Embed color (hex)
        fields (list): List of field dictionaries [{"name": "Field1", "value": "Value1", "inline": True}]
        footer_text (str): Footer text
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not webhook_url:
        return False
    
    embed = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    if fields:
        embed["fields"] = fields
    
    if footer_text:
        embed["footer"] = {"text": footer_text}
    
    payload = {
        "embeds": [embed]
    }
    
    try:
        response = requests.post(
            webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        return response.status_code == 204
    except Exception as e:
        print(f"Discord notification failed: {e}")
        return False


def send_subdomain_notification(webhook_url, project_name, new_subs_count, new_alive_count, sample_subs=None):
    """
    Send notification for new subdomains discovered
    
    Args:
        webhook_url (str): Discord webhook URL
        project_name (str): Name of the project
        new_subs_count (int): Number of new subdomains discovered
        new_alive_count (int): Number of alive subdomains
        sample_subs (list): Sample of new subdomains (max 5)
    """
    if not webhook_url or new_subs_count == 0:
        return False
    
    description = f"**{new_subs_count}** new subdomains discovered in project **{project_name}**\n**{new_alive_count}** are alive"
    
    fields = []
    
    if sample_subs and len(sample_subs) > 0:
        # Limit to 5 sample subdomains
        sample_text = "\n".join(sample_subs[:5])
        fields.append({
            "name": "Sample Subdomains",
            "value": f"```\n{sample_text}\n```",
            "inline": False
        })
    
    return send_discord_notification(
        webhook_url=webhook_url,
        title="🔍 New Subdomains Discovered",
        description=description,
        color=0x00ff00,  # Green
        fields=fields,
        footer_text=f"Total: {new_subs_count} subdomains"
    )


def send_vulnerability_notification(webhook_url, project_name, vulnerability_count, severity, sample_vulns=None):
    """
    Send notification for new vulnerabilities discovered
    
    Args:
        webhook_url (str): Discord webhook URL
        project_name (str): Name of the project
        vulnerability_count (int): Number of vulnerabilities found
        severity (str): Severity level (critical, high, medium, low, info)
        sample_vulns (list): Sample of vulnerabilities (max 3)
    """
    if not webhook_url or vulnerability_count == 0:
        return False
    
    # Color based on severity
    severity_colors = {
        "critical": 0xff0000,  # Red
        "high": 0xff6600,     # Orange
        "medium": 0xffff00,   # Yellow
        "low": 0x00ff00,      # Green
        "info": 0x0099ff       # Blue
    }
    color = severity_colors.get(severity.lower(), 0xffff00)
    
    description = f"**{vulnerability_count}** new vulnerabilities found in project **{project_name}**\n**Severity: {severity.upper()}**"
    
    fields = []
    
    if sample_vulns and len(sample_vulns) > 0:
        sample_text = "\n".join(sample_vulns[:3])
        fields.append({
            "name": "Sample Vulnerabilities",
            "value": f"```\n{sample_text}\n```",
            "inline": False
        })
    
    return send_discord_notification(
        webhook_url=webhook_url,
        title="🚨 New Vulnerabilities Discovered",
        description=description,
        color=color,
        fields=fields,
        footer_text=f"Total: {vulnerability_count} vulnerabilities"
    )


def send_directory_notification(webhook_url, project_name, new_dirs_count, sample_dirs=None):
    """
    Send notification for new directories discovered
    
    Args:
        webhook_url (str): Discord webhook URL
        project_name (str): Name of the project
        new_dirs_count (int): Number of new directories found
        sample_dirs (list): Sample of directories (max 5)
    """
    if not webhook_url or new_dirs_count == 0:
        return False
    
    description = f"**{new_dirs_count}** new directories discovered in project **{project_name}**"
    
    fields = []
    
    if sample_dirs and len(sample_dirs) > 0:
        sample_text = "\n".join(sample_dirs[:5])
        fields.append({
            "name": "Sample Directories",
            "value": f"```\n{sample_text}\n```",
            "inline": False
        })
    
    return send_discord_notification(
        webhook_url=webhook_url,
        title="📁 New Directories Discovered",
        description=description,
        color=0x0099ff,  # Blue
        fields=fields,
        footer_text=f"Total: {new_dirs_count} directories"
    )


def send_secret_notification(webhook_url, project_name, new_secrets_count, sample_secrets=None):
    """
    Send notification for new secrets discovered
    
    Args:
        webhook_url (str): Discord webhook URL
        project_name (str): Name of the project
        new_secrets_count (int): Number of secrets found
        sample_secrets (list): Sample of secrets (max 3)
    """
    if not webhook_url or new_secrets_count == 0:
        return False
    
    description = f"**{new_secrets_count}** new secrets discovered in project **{project_name}**"
    
    fields = []
    
    if sample_secrets and len(sample_secrets) > 0:
        # Sanitize secrets for display (hide potentially sensitive info)
        sample_text = []
        for secret in sample_secrets[:3]:
            # Show only first few characters of each secret
            if len(secret) > 10:
                sample_text.append(secret[:8] + "...")
            else:
                sample_text.append(secret)
        sample_text = "\n".join(sample_text)
        
        fields.append({
            "name": "Sample Secrets (truncated)",
            "value": f"```\n{sample_text}\n```",
            "inline": False
        })
    
    return send_discord_notification(
        webhook_url=webhook_url,
        title="🔑 New Secrets Discovered",
        description=description,
        color=0xff00ff,  # Magenta
        fields=fields,
        footer_text=f"Total: {new_secrets_count} secrets"
    )


def is_valid_webhook_url(webhook_url):
    """
    Basic validation of Discord webhook URL
    
    Args:
        webhook_url (str): Discord webhook URL to validate
    
    Returns:
        bool: True if valid format, False otherwise
    """
    if not webhook_url:
        return False
    
    try:
        parsed = urllib.parse.urlparse(webhook_url)
        return (parsed.scheme in ['http', 'https'] and 
                'discord.com' in parsed.netloc and 
                'webhooks' in parsed.path)
    except Exception:
        return False