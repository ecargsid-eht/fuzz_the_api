import os
import resend
from markdown_it import MarkdownIt
from src.core.config import settings

def send_security_report(target_email: str, job_id: int, target_url: str, report_content: str, pdf_path: str):
    """
    Renders the Markdown as a styled HTML email body and attaches the generated PDF.
    """
    resend.api_key = settings.RESEND_API_KEY
    
    # 1. Convert Markdown to HTML
    md = MarkdownIt()
    html_content = md.render(report_content)
    
    # 2. Wrap HTML in a clean CSS template (GitHub-like styling)
    styled_html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
            h1, h2, h3 {{ border-bottom: 1px solid #eaecef; padding-bottom: 0.3em; margin-top: 24px; }}
            pre {{ background-color: #f6f8fa; padding: 16px; overflow: auto; border-radius: 6px; font-family: monospace; font-size: 13px; }}
            code {{ background-color: rgba(27,31,35,0.05); padding: 0.2em 0.4em; border-radius: 3px; font-family: monospace; font-size: 13px; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 16px; }}
            th, td {{ padding: 8px 13px; border: 1px solid #dfe2e5; }}
            th {{ background-color: #f6f8fa; font-weight: 600; }}
            blockquote {{ border-left: 4px solid #dfe2e5; color: #6a737d; padding: 0 1em; margin: 0; }}
        </style>
    </head>
    <body>
        <p>The automated security fuzzer has completed the scan for <strong>{target_url}</strong>.</p>
        <p>You can review the findings below or download the attached PDF for your records.</p>
        <hr>
        {html_content}
    </body>
    </html>
    """
    
    # 3. Read the generated PDF into bytes for Resend
    with open(pdf_path, "rb") as f:
        pdf_bytes = list(f.read())
        
    # 4. Construct the Resend Payload
    params: resend.Emails.SendParams = {
        "from": "Security Fuzzer <onboarding@resend.dev>",
        "to": [target_email],
        "subject": f"🚨 API Security Scan Completed - Job #{job_id}",
        "html": styled_html,
        "attachments": [
            {
                "filename": f"security_report_job_{job_id}.pdf",
                "content": pdf_bytes 
            }
        ]
    }
    
    # 5. Send the email
    try:
        response = resend.Emails.send(params)
        print(f"📧 Security report for Job {job_id} successfully sent via Resend. (ID: {response.get('id')})")
    except Exception as e:
        print(f"❌ Failed to send email via Resend: {e}")