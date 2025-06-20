import re
import html
from urllib.parse import urlparse

def sanitize_input(input_string):
    """Sanitize user input to prevent XSS and other attacks"""
    if not input_string:
        return ""
    
    # HTML escape the input
    sanitized = html.escape(input_string)
    
    # Remove null bytes
    sanitized = sanitized.replace('\x00', '')
    
    # Limit length
    sanitized = sanitized[:1000]
    
    return sanitized

def validate_domain(domain):
    """Validate domain name format"""
    if not domain:
        return False
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
    
    # Basic domain validation regex
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    if not domain_regex.match(domain):
        return False
    
    # Check length
    if len(domain) > 253:
        return False
    
    # Check each label length
    labels = domain.split('.')
    for label in labels:
        if len(label) > 63:
            return False
    
    return True

def validate_email(email):
    """Validate email address format"""
    if not email:
        return False
    
    email_regex = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    return email_regex.match(email) is not None
