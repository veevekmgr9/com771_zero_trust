import os
import tempfile
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from pypdf import PdfReader, PdfWriter

def build_patient_pdf(patient, generated_by, output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()
    story = []

    title = Paragraph("Secure Patient Record Export", styles["Title"])
    subtitle = Paragraph(
        f"Generated for internal use by: <b>{generated_by}</b><br/>Generated at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        styles["BodyText"],
    )

    story.append(title)
    story.append(Spacer(1, 8))
    story.append(subtitle)
    story.append(Spacer(1, 16))

    data = [
        ["Field", "Value"],
        ["Patient ID", str(patient["id"])],
        ["Patient Name", patient["patient_name"]],
        ["Age", str(patient["age"]) if patient["age"] is not None else "-"],
        ["Disease", patient["disease"] or "-"],
        ["Doctor Assigned", patient["doctor_assigned"] or "-"],
        ["Diagnosis", patient["diagnosis_encrypted"] or "-"],
    ]

    table = Table(data, colWidths=[55 * mm, 105 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbeafe")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#f8fafc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))

    story.append(table)
    story.append(Spacer(1, 16))

    note = Paragraph(
        "Confidential: This document is password protected and intended only for authorized access.",
        styles["Italic"],
    )
    story.append(note)

    doc.build(story)


def encrypt_pdf(input_pdf_path, output_pdf_path, user_password, owner_password):
    reader = PdfReader(input_pdf_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.encrypt(
        user_password=user_password,
        owner_password=owner_password,
        algorithm="AES-256",
    )

    with open(output_pdf_path, "wb") as f:
        writer.write(f)


def generate_encrypted_patient_pdf(patient, generated_by, user_password, owner_password):
    temp_dir = tempfile.mkdtemp(prefix="patient_pdf_")
    plain_pdf = os.path.join(temp_dir, f"patient_{patient['id']}_plain.pdf")
    encrypted_pdf = os.path.join(temp_dir, f"patient_{patient['id']}_secure.pdf")

    build_patient_pdf(patient, generated_by, plain_pdf)
    encrypt_pdf(plain_pdf, encrypted_pdf, user_password, owner_password)

    return encrypted_pdf