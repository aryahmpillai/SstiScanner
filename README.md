# SSTI Vulnerability Scanner

A tool for detecting Server-Side Template Injection vulnerabilities in web applications.


## Features

- Detect SSTI vulnerabilities across multiple template engines:
  - Jinja2 (Python)
  - Twig (PHP)
  - Pebble (Java)
  - Velocity (Java)
  - FreeMarker (Java)
  - Mako (Python)
  - ERB (Ruby)
- Support for both GET and POST requests
- Customizable scanning options
- Detailed vulnerability reporting
- Color-coded console output
- Result export to file

To get started, clone the repository to your local machine:

```bash
git clone https://github.com/aryahmpillai/SstiScanner.git

cd SstiScanner

Setup the Virtual Environment
python -m venv venv

On macOS/Linux:
source venv/bin/activate

On Windows:
venv\Scripts\activate

Install Dependencies.
pip install -r requirements.txt

Usage 💻
For Single URL 🌐  python main.py http://example.com/page

For Multiple URLs  📄 python main.py -f urls.txt
