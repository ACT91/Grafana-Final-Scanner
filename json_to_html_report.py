#!/usr/bin/env python3
"""
Independent JSON to HTML Report Converter
Converts Grafana Final Scanner JSON reports to browsable HTML format
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime
import html as html_escape


def load_json_report(json_file: str) -> list:
    """Load and parse JSON report file"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{json_file}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{json_file}': {str(e)}")
        sys.exit(1)


def generate_html_report(results: list) -> str:
    """Generate HTML report from results data"""
    
    # Calculate statistics
    total_targets = len(results)
    vulnerable_targets = sum(1 for r in results if r.get('vulnerabilities'))
    total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results)
    
    # Count severity levels
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for result in results:
        for vuln in result.get('vulnerabilities', []):
            severity = vuln.get('severity', 'UNKNOWN')
            if severity in severity_counts:
                severity_counts[severity] += 1
    
    # Build vulnerability rows
    vuln_rows_html = ""
    if total_vulns == 0:
        vuln_rows_html = '<tr><td colspan="6" style="text-align: center; padding: 20px; color: #28a745;">No vulnerabilities detected</td></tr>'
    else:
        for result in results:
            if result.get('vulnerabilities'):
                for vuln in result['vulnerabilities']:
                    severity = vuln.get('severity', 'UNKNOWN')
                    severity_color = {
                        'CRITICAL': '#dc3545',
                        'HIGH': '#fd7e14',
                        'MEDIUM': '#ffc107',
                        'LOW': '#17a2b8'
                    }.get(severity, '#6c757d')
                    
                    vuln_rows_html += f"""
                    <tr>
                        <td><a href="{html_escape.escape(result.get('url', ''))}" target="_blank">{html_escape.escape(result.get('url', ''))}</a></td>
                        <td>{html_escape.escape(str(result.get('version') or 'Unknown'))}</td>
                        <td><span style="background: {severity_color}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">{severity}</span></td>
                        <td><code>{html_escape.escape(vuln.get('cve_id', ''))}</code></td>
                        <td>{html_escape.escape(vuln.get('message', ''))}</td>
                        <td><a href="{html_escape.escape(vuln.get('test_url', ''))}" target="_blank" style="font-size: 11px;">Test URL</a></td>
                    </tr>
                    """
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔒 Grafana Security Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: #0a0e27; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; background: #1a1a2e; padding: 40px; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.5); }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; border: 1px solid #2a2a4a; }}
        .header h1 {{ color: #ff4444; font-size: 28px; }}
        .header p {{ color: #888; margin-top: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: #1a1a2e; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #2a2a4a; }}
        .stat-card h3 {{ font-size: 14px; color: #888; margin-bottom: 10px; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; }}
        .stat-card .critical {{ color: #dc3545; }}
        .stat-card .safe {{ color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; background: #1a1a2e; border-radius: 8px; overflow: hidden; border: 1px solid #2a2a4a; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #2a2a4a; }}
        th {{ background: #16213e; color: #888; font-size: 12px; text-transform: uppercase; }}
        tr:hover {{ background: #1f1f35; }}
        a {{ color: #0dcaf0; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        code {{ background: #2a2a4a; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
        .footer {{ text-align: center; margin-top: 30px; color: #555; font-size: 12px; }}
        .severity-dist {{ display: flex; gap: 10px; margin: 20px 0; }}
        .severity-bar {{ height: 20px; border-radius: 3px; min-width: 4px; }}
        h2 {{ margin-top: 20px; margin-bottom: 15px; color: #0dcaf0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Grafana Security Scan Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Targets: {total_targets}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Targets Scanned</h3>
                <div class="value safe">{total_targets}</div>
            </div>
            <div class="stat-card">
                <h3>Vulnerable</h3>
                <div class="value critical">{vulnerable_targets}</div>
            </div>
            <div class="stat-card">
                <h3>Secure</h3>
                <div class="value safe">{total_targets - vulnerable_targets}</div>
            </div>
            <div class="stat-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value critical">{total_vulns}</div>
            </div>
        </div>

        <h2 style="margin-bottom: 15px;">Severity Distribution</h2>
        <div class="severity-dist">
            <div><strong>🔴 CRITICAL:</strong> {severity_counts['CRITICAL']}</div>
            <div><strong>🟠 HIGH:</strong> {severity_counts['HIGH']}</div>
            <div><strong>🟡 MEDIUM:</strong> {severity_counts['MEDIUM']}</div>
            <div><strong>🔵 LOW:</strong> {severity_counts['LOW']}</div>
        </div>
        
        <h2 style="margin-bottom: 15px;">Vulnerability Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Version</th>
                    <th>Severity</th>
                    <th>CVE ID</th>
                    <th>Description</th>
                    <th>Test URL</th>
                </tr>
            </thead>
            <tbody>
                {vuln_rows_html}
            </tbody>
        </table>
        
        <div class="footer">
            <p>Generated by JSON to HTML Report Converter | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""
    
    return html_content


def save_html_report(html_content: str, output_file: str):
    """Save HTML content to file"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"✓ HTML report saved: {output_file}")
    except Exception as e:
        print(f"Error saving HTML report: {str(e)}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Convert Grafana Final Scanner JSON report to browsable HTML',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python json_to_html_report.py report.json
  python json_to_html_report.py report.json -o custom_report.html
  python json_to_html_report.py report_1001.json -o output.html
        """
    )
    
    parser.add_argument('json_file', help='Path to JSON report file')
    parser.add_argument('-o', '--output', help='Output HTML file (default: same name with .html extension)')
    
    args = parser.parse_args()
    
    # Load JSON report
    print(f"Loading report from: {args.json_file}")
    results = load_json_report(args.json_file)
    print(f"Loaded {len(results)} targets")
    
    # Determine output filename
    output_file = args.output
    if not output_file:
        json_path = Path(args.json_file)
        output_file = str(json_path.with_suffix('.html'))
    
    # Generate and save HTML
    print("Generating HTML report...")
    html_content = generate_html_report(results)
    save_html_report(html_content, output_file)
    
    print(f"Done! Open {output_file} in your browser")


if __name__ == '__main__':
    main()
