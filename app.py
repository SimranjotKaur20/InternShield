from flask import Flask, render_template, request
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import Table
from flask import send_file
import io
import PyPDF2
import re
import whois
from datetime import datetime
import requests

app = Flask(__name__)
# -------------------------------------------------
# Home Route
# -------------------------------------------------

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

@app.route("/awareness")
def awareness():
    return render_template("awareness.html")

@app.route("/domain")
def domain():
    return render_template("domain.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/check_domain", methods=["POST"])
def check_domain():

    domain = request.form.get("domain")

    API_KEY = "Mj7ORGZQ0PhSWxnro1rdC2DOouHqCKpC"
    url = f"https://ipqualityscore.com/api/json/url/{API_KEY}/{domain}"

    response = requests.get(url)
    data = response.json()

    domain_age_data = data.get("domain_age", {})
    domain_age = domain_age_data.get("human", "Unknown")

    phishing = data.get("phishing", False)
    malware = data.get("malware", False)
    suspicious = data.get("suspicious", False)

    if phishing or malware or suspicious:
        verdict = "⚠ Dangerous Domain"
        verdict_color = "red"
    else:
        verdict = "✔ Safe Domain"
        verdict_color = "green"

    return render_template(
        "domain_result.html",
        domain=domain,
        domain_age=domain_age,
        phishing=phishing,
        malware=malware,
        suspicious=suspicious,
        verdict=verdict,
        verdict_color=verdict_color
    )

from urllib.parse import urlparse

def extract_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        return domain.replace("www.", "")
    except:
        return ""
def detect_scam(text):

    score = 0
    indicators = set()
    explanation = set()
    text_lower = text.lower()

    # URL detection
    urls = re.findall(r'https?://\S+', text_lower)
    domain_details = []

    # ----------------------------
    # Basic keywords
    # ----------------------------
    basic_keywords = [
        "registration fee", "security deposit", "refundable payment",
        "limited seats", "urgent payment", "processing fee",
        "guaranteed placement", "selected without interview",
        "discounted fee", "book your seat", "payment details",
        "exclusive offer", "only 5 seats", "take action now",
        "id card", "id card registration", "registration payment",
        "pay ₹", "rs.", "₹", "payment", "pay now", "limited spots",
        "complete registration", "register here",
        "priority support", "program access fee"
    ]

    suspicious_phrases = [
        "act fast",
        "limited time",
        "exclusive opportunity",
        "immediate payment"
    ]

    for keyword in basic_keywords:
        if keyword in text_lower:
            score += 15
            indicators.add(keyword)

    # ----------------------------
    # Internship Payment Scam Detection
    # ----------------------------
    payment_words = ["₹", "rs", "rupees", "payment", "fee", "registration"]

    if "internship" in text_lower and any(word in text_lower for word in payment_words):
        score += 40
        indicators.add("internship payment scam")
        explanation.add("Internship asks for payment which is a common scam pattern.")

    # ----------------------------
    # WhatsApp detection
    # ----------------------------
    if "whatsapp" in text_lower:
        score += 20
        indicators.add("whatsapp onboarding pattern")

    # ----------------------------
    # Salary detection
    # ----------------------------
    if "lpa" in text_lower:
        score += 20
        indicators.add("salary promise pattern")

    # ----------------------------
    # Remote + flexible
    # ----------------------------
    if "remote" in text_lower and "flexible" in text_lower:
        score += 15
        indicators.add("too flexible remote internship")

    if "no interview" in text_lower:
        score += 20
        indicators.add("no interview selection")

    # ----------------------------
    # URL checks
    # ----------------------------
    if len(urls) >= 2:
        score += 20
        indicators.add("multiple external platforms")

    suspicious_tlds = [".xyz", ".top", ".click", ".online", ".site"]

    for url in urls:
        if any(tld in url for tld in suspicious_tlds):
            score += 20
            indicators.add("suspicious domain extension")

    shorteners = ["bit.ly", "tinyurl", "rb.gy", "cut.ly", "t.co"]

    for url in urls:
        if any(short in url for short in shorteners):
            score += 20
            indicators.add("shortened link used")

    # ----------------------------
    # Domain intelligence
    # ----------------------------
    domains = set()

    for url in urls:
        domain = extract_domain(url)
        if domain:
            domains.add(domain)

    unique_domains = list(domains)

    if len(unique_domains) > 1:
        score += 25
        indicators.add("multiple unrelated domains used")
        explanation.add("Multiple external domains detected in single offer.")

    for domain in unique_domains:
        if domain.count('.') >= 3:
            score += 15
            indicators.add("complex subdomain structure")
            explanation.add("Suspicious multi-level subdomain detected.")

    # ----------------------------
    # Domain age check
    # ----------------------------
    for domain in domains:
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                domain_age_days = (datetime.now() - creation_date).days
                
                domain_details.append(f"{domain} registered {domain_age_days} days ago")
                
                if domain_age_days < 180:
                    score += 25
                    indicators.add("newly registered domain")
        except:
            pass

    # ----------------------------
    # Email vs domain mismatch
    # ----------------------------
    email_domains = re.findall(r'@([\w.-]+)', text_lower)

    if email_domains and domains:
        email_base = ".".join(email_domains[0].split('.')[-2:])

        for domain in domains:
            domain_base = ".".join(domain.split('.')[-2:])
            if email_base != domain_base:
                score += 25
                indicators.add("email and website domain mismatch")
                explanation.add("Sender email domain does not match linked website domain.")
                break

    # ----------------------------
    # Marketing language
    # ----------------------------
    marketing_words = [
        "exciting opportunity",
        "thrilled",
        "warmest congratulations",
        "streamline your onboarding",
        "eagerly await your arrival",
        "get ready to code"
    ]

    if any(word in text_lower for word in marketing_words):
        score += 10
        indicators.add("marketing-heavy language")

    # ----------------------------
    # Cap score
    # ----------------------------
    if score > 100:
        score = 100

    # ----------------------------
    # Risk classification
    # ----------------------------
    if score <= 30:
        risk = "Low Risk"
    elif score <= 60:
        risk = "Suspicious"
    else:
        risk = "High Scam Risk"

    return score, risk, list(indicators), list(explanation), domain_details
   
# -------------------------------------------------
# Analyze Route
# -------------------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():

    text_content = request.form.get("content", "")
    url_input = request.form.get("url_input", "")

    if url_input:
        text_content += " " + url_input

    pdf_files = request.files.getlist("pdf_file")

    # Extract text from PDFs
    for pdf_file in pdf_files:
        if pdf_file and pdf_file.filename != "":
            reader = PyPDF2.PdfReader(pdf_file)
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text_content += extracted

    # Detect scam
    score, risk, indicators, explanation, domain_details = detect_scam(text_content)

    return render_template(
        "result.html",
        score=score,
        risk=risk,
        keywords=indicators,
        explanation=explanation
    )
@app.route("/download_report", methods=["POST"])
def download_report():

    score = request.form.get("score")
    risk = request.form.get("risk")
    indicators = request.form.getlist("keywords")
    explanation = request.form.getlist("explanation")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer)

    elements = []
    styles = getSampleStyleSheet()

    # Title
    title_style = styles["Heading1"]
    elements.append(Paragraph("InternShield Scam Analysis Report", title_style))
    elements.append(Spacer(1, 0.3 * inch))

    # Risk & Score Table
    data = [
        ["Risk Level", risk],
        ["Scam Probability", f"{score}%"]
    ]

    table = Table(data, colWidths=[2.5 * inch, 2.5 * inch])
    table.setStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('BACKGROUND', (0, 1), (-1, 1), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey)
    ])

    elements.append(table)
    elements.append(Spacer(1, 0.4 * inch))

    # Indicators Section
    elements.append(Paragraph("Detected Indicators:", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    indicator_list = [ListItem(Paragraph(item, styles["Normal"])) for item in indicators]
    elements.append(ListFlowable(indicator_list, bulletType='bullet'))
    elements.append(Spacer(1, 0.4 * inch))

    # Explanation Section
    if explanation:
        elements.append(Paragraph("Why This Might Be a Scam:", styles["Heading2"]))
        elements.append(Spacer(1, 0.2 * inch))

        explanation_list = [ListItem(Paragraph(item, styles["Normal"])) for item in explanation]
        elements.append(ListFlowable(explanation_list, bulletType='bullet'))

    doc.build(elements)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="InternShield_Report.pdf",
        mimetype="application/pdf"
    )
# -------------------------------------------------
# Run App
# -------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)