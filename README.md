# NetGuard — PCAP Threat Analyzer

NetGuard is an automated PCAP analysis platform that turns raw packet captures into clear, actionable security insights. It features a monochrome dark UI with glassmorphism styling, interactive charts, geolocation mapping, and heuristic threat detection (Reconnaissance and Brute Force, among others).

## Features
- Upload and analyze PCAP files with a 50MB upload limit
- Dashboard with traffic stats, charts, and session table
- Geo Map with dark tiles, IP markers, and popups showing country, city, region, organization
- Threats page with separate sections for Reconnaissance (Port Scan) and Brute Force attempts
- Credentials page listing detected clear‑text usernames and passwords
- About page with core concepts and industry context

## Getting Started
### Prerequisites
- Python 3.10+ recommended
- Pip for dependency management

### Install dependencies
```bash
pip install -r requirements.txt
```

### Run the application
```bash
python app.py
```
Then open http://localhost:5000/ in your browser.

## Usage
1. Go to Home and upload a PCAP file
2. After analysis, you will be redirected to the Dashboard
3. Navigate:
   - Geo Map: visualize IPs and locations
   - Threats: view detected threats; use top buttons to jump to Reconnaissance or Brute Force tables
   - Credentials: inspect clear‑text credentials found
   - About: learn core concepts and platform details

## Sample Data
Generate a sample PCAP for testing:
```bash
python generate_test_pcap.py
```
Upload the generated test_traffic.pcap from the Home page.

## API
- GET /api/data/<id> returns JSON for the current analysis session, including stats, sessions, threats, and geo data.

## Project Structure
- Application: [app.py](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/app.py)
- Analysis:
  - Parser: [analysis/parser.py](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/analysis/parser.py)
  - Threat detectors: [analysis/detectors.py](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/analysis/detectors.py)
  - GeoIP resolution: [analysis/geoip.py](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/analysis/geoip.py)
- Templates:
  - Base layout: [templates/base.html](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/templates/base.html)
  - Home: [templates/index.html](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/templates/index.html)
  - Dashboard: [templates/dashboard.html](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/templates/dashboard.html)
  - Geo Map: [templates/geo.html](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/templates/geo.html)
  - Threats: [templates/threats.html](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/templates/threats.html)
  - Credentials: [templates/credentials.html](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/templates/credentials.html)
  - About: [templates/about.html](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/templates/about.html)
- Static JS:
  - Geo logic: [static/js/geo.js](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/static/js/geo.js)
  - Dashboard logic: [static/js/dashboard.js](file:///c:/Users/csp/Documents/trae_projects/PCAP_analyzer/static/js/dashboard.js)

## Notes
- GeoIP uses the free ip-api.com endpoint with rate limits; for production, use a paid API or local MMDB.
- Upload size is limited to 50MB and stored temporarily in the uploads directory.
- The app runs in debug mode on port 5000 by default.

