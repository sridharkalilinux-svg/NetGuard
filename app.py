import os
import uuid
import ujson
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename
from analysis.parser import analyze_pcap
from analysis.detectors import ThreatDetector
from analysis.geoip import resolve_batch

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.abspath('uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024 # 50MB limit

# Ensure upload dir exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# In-memory storage for demo purposes
ANALYSIS_RESULTS = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_{filename}")
        file.save(save_path)
        
        try:
            # 1. Parse
            results = analyze_pcap(save_path)
            if not results:
                 return jsonify({'error': 'Failed to parse PCAP'}), 500
                 
            # 2. Detect Threats
            detector = ThreatDetector()
            threats = detector.detect_all(results)
            
            # 3. GeoIP (Top Talkers)
            ips = list(results['stats']['ips'])
            # Limit to top 50 unique IPs to save time/api limits
            geo_data = resolve_batch(ips[:50])
            
            # Store
            ANALYSIS_RESULTS[file_id] = {
                'filename': filename,
                'stats': results['stats'],
                'sessions': results['sessions'],
                'threats': threats,
                'geo': geo_data
            }
            
            return jsonify({'success': True, 'id': file_id, 'redirect': url_for('dashboard', id=file_id)})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/dashboard/<id>')
def dashboard(id):
    if id not in ANALYSIS_RESULTS: return redirect(url_for('index'))
    return render_template('dashboard.html', id=id)

@app.route('/geo/<id>')
def geo(id):
    if id not in ANALYSIS_RESULTS: return redirect(url_for('index'))
    return render_template('geo.html', id=id)

@app.route('/threats/<id>')
def threats(id):
    if id not in ANALYSIS_RESULTS: return redirect(url_for('index'))
    return render_template('threats.html', id=id)

@app.route('/credentials/<id>')
def credentials(id):
    if id not in ANALYSIS_RESULTS: return redirect(url_for('index'))
    return render_template('credentials.html', id=id)
    
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/api/data/<id>')
def get_data(id):
    if id not in ANALYSIS_RESULTS: return jsonify({'error': 'Not found'}), 404
    return app.response_class(
        response=ujson.dumps(ANALYSIS_RESULTS[id]),
        status=200,
        mimetype='application/json'
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)
