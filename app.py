from flask import Flask, render_template, request, jsonify, redirect, url_for
import re
from collections import defaultdict
import os
from datetime import datetime
import json

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def analyze_log_file(file_path, threshold=3):
    """Analyze log file and return results"""
    failed_attempts = defaultdict(int)
    total_lines = 0
    failed_lines = 0
    
    try:
        with open(file_path, "r", encoding='utf-8', errors='ignore') as file:
            for line in file:
                total_lines += 1
                if "Failed password" in line:
                    failed_lines += 1
                    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        failed_attempts[ip] += 1
    except Exception as e:
        return {"error": f"Error reading file: {str(e)}"}
    
    # Categorize IPs
    suspicious_ips = {}
    normal_ips = {}
    
    for ip, count in failed_attempts.items():
        if count >= threshold:
            suspicious_ips[ip] = count
        else:
            normal_ips[ip] = count
    
    return {
        "total_lines": total_lines,
        "failed_lines": failed_lines,
        "suspicious_ips": suspicious_ips,
        "normal_ips": normal_ips,
        "total_unique_ips": len(failed_attempts),
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "threshold": threshold
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # Check if file was uploaded
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    # Get threshold from form
    threshold = int(request.form.get('threshold', 3))
    
    # Save uploaded file
    filename = f"uploaded_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    
    # Analyze the file
    results = analyze_log_file(filepath, threshold)
    
    # Clean up uploaded file
    try:
        os.remove(filepath)
    except:
        pass
    
    return jsonify(results)

@app.route('/analyze_default', methods=['GET'])
def analyze_default():
    """Analyze the default auth.log file"""
    default_file = "auth.log"
    if not os.path.exists(default_file):
        return jsonify({"error": "Default auth.log file not found"}), 404
    
    threshold = int(request.args.get('threshold', 3))
    results = analyze_log_file(default_file, threshold)
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
