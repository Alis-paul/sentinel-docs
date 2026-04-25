import fitz
from PIL import Image, ImageDraw, ImageFont
import pytesseract
from pdf2image import convert_from_bytes
import io
import re

# Configure paths
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
POPPLER_PATH = r"C:\Users\Happy\Downloads\Release-25.12.0-0\poppler-25.12.0\Library\bin"


def extract_text_from_pdf(file_bytes):
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    text = ""
    for page in doc:
        text += page.get_text()
    if not text.strip():
        pages = convert_from_bytes(file_bytes, poppler_path=POPPLER_PATH)
        for page_img in pages:
            text += pytesseract.image_to_string(page_img) + "\n"
    return text


def extract_text_from_image(file_bytes):
    image = Image.open(io.BytesIO(file_bytes))
    return pytesseract.image_to_string(image)


def get_all_chunks(match_text):
    """
    Break a mask target into matchable OCR word chunks.
    For short tokens (< 5 chars), only exact match is used.
    """
    chunks = {match_text.lower()}
    for part in match_text.split():
        if len(part) >= 3:
            chunks.add(part.lower())
    for d in re.findall(r'\d{3,}', match_text):
        chunks.add(d)
    return chunks


def collect_mask_targets(findings):
    """
    Returns a flat set of strings that should actually be redacted.
    Uses mask_targets (e.g. only surname for Name) and respects should_mask flag.
    """
    targets = set()
    for finding in findings:
        if not finding.get("should_mask", True):
            continue  # e.g. BloodGroup — skip masking
        mask_list = finding.get("mask_targets") or finding.get("matches", [])
        for t in mask_list:
            t = t.strip()
            if t:
                targets.add(t)
    return targets


def mask_image_with_boxes(image, findings):
    draw = ImageDraw.Draw(image)
    data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    try:
        font = ImageFont.truetype("arial.ttf", 16)
    except Exception:
        font = ImageFont.load_default()

    # Build chunk set only from maskable targets
    mask_targets = collect_mask_targets(findings)
    all_chunks = set()
    for target in mask_targets:
        all_chunks.update(get_all_chunks(target))

    n = len(data["text"])
    for i in range(n):
        word = data["text"][i].strip().lower()
        if not word or len(word) < 3:
            continue
        if int(data["conf"][i]) < 30:
            continue

        for chunk in all_chunks:
            if word == chunk or (len(chunk) >= 5 and chunk in word) or (len(word) >= 5 and word in chunk):
                x, y, w, h = data["left"][i], data["top"][i], data["width"][i], data["height"][i]
                draw.rectangle([x - 4, y - 4, x + w + 4, y + h + 4], fill="white", outline="lightgray")
                draw.text((x + w // 2, y + h // 2), "XXX", fill="red", font=font, anchor="mm")
                break

    return image


def mask_image(file_bytes, findings):
    image = Image.open(io.BytesIO(file_bytes)).convert("RGB")
    masked = mask_image_with_boxes(image, findings)

    pdf_doc = fitz.open()
    img_byte_arr = io.BytesIO()
    masked.save(img_byte_arr, format="JPEG")

    page = pdf_doc.new_page(width=masked.width, height=masked.height)
    page.insert_image(page.rect, stream=img_byte_arr.getvalue())
    return pdf_doc.tobytes()


def mask_scanned_pdf(file_bytes, findings):
    pages = convert_from_bytes(file_bytes, poppler_path=POPPLER_PATH)
    masked_pages = []
    for page_img in pages:
        masked = mask_image_with_boxes(page_img.convert("RGB"), findings)
        masked_pages.append(masked)

    pdf_bytes = io.BytesIO()
    masked_pages[0].save(pdf_bytes, format="PDF", save_all=True, append_images=masked_pages[1:])
    return pdf_bytes.getvalue()


def mask_pdf_text(file_bytes, findings):
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    mask_targets = collect_mask_targets(findings)

    for page in doc:
        for target in mask_targets:
            areas = page.search_for(target)
            for area in areas:
                page.add_redact_annot(area, fill=(1, 1, 1))
        page.apply_redactions()

    return doc.tobytes()