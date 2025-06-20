import json
import subprocess
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, session
from app import app
from validators import validate_domain, sanitize_input
import logging

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        try:
            # Get and validate form data
            domain = sanitize_input(request.form.get('domain', '').strip())
            selected_modules = request.form.getlist('modules')
            
            # Validate domain
            if not validate_domain(domain):
                flash('Please enter a valid domain name.', 'error')
                return render_template('scan.html')
            
            # Validate modules
            valid_modules = ['osint', 'subdomain', 'hosts', 'web']
            selected_modules = [m for m in selected_modules if m in valid_modules]
            
            if not selected_modules:
                flash('Please select at least one scan module.', 'error')
                return render_template('scan.html')
            
            # Execute scan
            results = execute_scan(domain, selected_modules)
            
            # Store scan data in session for results page
            scan_data = {
                'domain': domain,
                'modules': selected_modules,
                'results': results,
                'status': 'completed',
                'created_at': datetime.now().isoformat(),
                'completed_at': datetime.now().isoformat()
            }
            session['last_scan'] = scan_data
            
            flash('Scan completed successfully!', 'success')
            return redirect(url_for('results'))
            
        except Exception as e:
            logging.error(f"Scan error: {str(e)}")
            flash('An error occurred during the scan. Please try again.', 'error')
    
    return render_template('scan.html')

@app.route('/results')
def results():
    scan_data = session.get('last_scan')
    if not scan_data:
        flash('No scan results available. Please run a scan first.', 'info')
        return redirect(url_for('scan'))
    
    return render_template('results.html', scan_result=scan_data, results=scan_data.get('results', {}))

def execute_scan(domain, modules):
    """Execute the ReconX CLI tool with selected modules"""
    results = {}
    
    for module in modules:
        try:
            # Build command - use python3 and full path
            cmd = f"python3 reconx.py {module} --domain {domain}"
            
            # Execute command with timeout
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd='/home/runner/workspace'
            )
            
            if result.returncode == 0:
                results[module] = {
                    'status': 'success',
                    'output': result.stdout,
                    'error': result.stderr if result.stderr else None
                }
            else:
                # Even if there's an error, show the output for debugging
                results[module] = {
                    'status': 'error',
                    'output': result.stdout if result.stdout else 'No output',
                    'error': result.stderr if result.stderr else 'Unknown error'
                }
                
        except subprocess.TimeoutExpired:
            results[module] = {
                'status': 'timeout',
                'output': '',
                'error': 'Command timed out after 5 minutes'
            }
        except Exception as e:
            results[module] = {
                'status': 'error',
                'output': '',
                'error': f'Execution error: {str(e)}'
            }
    
    return results

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500
