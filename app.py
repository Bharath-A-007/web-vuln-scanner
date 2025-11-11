from flask import Flask, render_template, request, send_file
import os
from scanner import scan_website, generate_pdf_report
import re

app = Flask(__name__)

def normalize_url(url):
    """Normalize URL by ensuring it has a proper scheme"""
    if not url:
        return url
        
    # Remove any whitespace
    url = url.strip()
    
    # Remove any existing http:// or https://
    url = re.sub(r'^https?://', '', url)
    
    # Add http:// if no scheme is specified
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    return url

@app.route('/', methods=['GET', 'POST'])
def index():
    result_dict = {}
    target_url = ""
    
    if request.method == 'POST':
        target_url = request.form.get('url')
        scan_type = request.form.get('scan_type', 'quick')
        
        if target_url:
            # Use the normalized URL function
            target_url = normalize_url(target_url)
                
            print(f"Scanning: {target_url} ({scan_type} scan)")
            result_dict = scan_website(target_url, comprehensive=(scan_type == 'comprehensive'))
    
    return render_template('index.html', result_list=result_dict, target_url=target_url)

@app.route('/download-report')
def download_report():
    target_url = request.args.get('url', '')
    
    if not target_url:
        return "No scan data available"
    
    # Generate the PDF report
    pdf_path = generate_pdf_report(target_url)
    
    # Return the file for download
    return send_file(pdf_path, as_attachment=True)

if __name__ == '__main__':
    if not os.path.exists('reports'):
        os.makedirs('reports')
    app.run(debug=True)
