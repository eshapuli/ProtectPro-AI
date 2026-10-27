import io
import logging
from typing import Tuple, Dict, Any, Optional
from PIL import Image, ImageOps, ImageFilter

logger = logging.getLogger(__name__)

# Check if pytesseract and engine binary are available
_PYTESSERACT_AVAILABLE = False
try:
    import pytesseract
    # Check if tesseract binary can be executed
    pytesseract.get_tesseract_version()
    _PYTESSERACT_AVAILABLE = True
except Exception:
    _PYTESSERACT_AVAILABLE = False

# Fallback: check if easyocr is installed
_EASYOCR_READER = None
try:
    import easyocr
    _EASYOCR_READER = easyocr.Reader(['en'], gpu=False)
except Exception:
    _EASYOCR_READER = None

def preprocess_image(image: Image.Image) -> Image.Image:
    """
    Applies image preprocessing:
    - Converts to grayscale
    - Auto-contrasts and sharpens to improve OCR recognition
    """
    gray = ImageOps.grayscale(image)
    contrasted = ImageOps.autocontrast(gray)
    sharpened = contrasted.filter(ImageFilter.SHARPEN)
    return sharpened

def extract_image_forensics(image: Image.Image) -> Dict[str, Any]:
    """
    Extracts safe image metadata and forensic dimensions without executing active code.
    """
    width, height = image.size
    aspect_ratio = round(width / height, 2) if height > 0 else 0
    format_name = image.format or "RAW"
    mode = image.mode
    
    return {
        "width": width,
        "height": height,
        "aspect_ratio": aspect_ratio,
        "format": format_name,
        "color_mode": mode
    }

def run_ocr_on_image(image_bytes: bytes) -> Tuple[str, Dict[str, Any], str]:
    """
    Executes OCR and forensic inspection on uploaded screenshot bytes.
    Returns:
    - extracted_text: str
    - forensics: dict
    - engine_used: str ("tesseract", "easyocr", or "fallback")
    """
    image = Image.open(io.BytesIO(image_bytes))
    forensics = extract_image_forensics(image)
    preprocessed = preprocess_image(image)
    
    extracted_text = ""
    engine_used = "none"

    if _PYTESSERACT_AVAILABLE:
        try:
            extracted_text = pytesseract.image_to_string(preprocessed)
            engine_used = "tesseract"
        except Exception as e:
            logger.warning(f"Tesseract execution error: {e}")

    if not extracted_text and _EASYOCR_READER is not None:
        try:
            # easyocr takes image array or bytes
            results = _EASYOCR_READER.readtext(image_bytes, detail=0)
            extracted_text = " ".join(results)
            engine_used = "easyocr"
        except Exception as e:
            logger.warning(f"EasyOCR execution error: {e}")

    if not extracted_text:
        # Transparent fallback notice when no OCR binary is present on host OS
        engine_used = "embedded_forensics_fallback"

    return extracted_text.strip(), forensics, engine_used
