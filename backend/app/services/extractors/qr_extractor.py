import io
import re
import numpy as np
from PIL import Image
from typing import Tuple, Optional, Dict, Any, List
import cv2

from app.schemas.analysis import IndicatorResult

def decode_qr_image(image_bytes: bytes) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Decodes QR code payload from image bytes using OpenCV.
    Safe: Decodes data strictly in memory without executing or resolving destinations.
    """
    image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    np_img = np.array(image)
    # Convert RGB to BGR for OpenCV
    opencv_img = cv2.cvtColor(np_img, cv2.COLOR_RGB2BGR)
    
    detector = cv2.QRCodeDetector()
    decoded_text, points, _ = detector.detectAndDecode(opencv_img)
    
    metadata = {
        "width": image.width,
        "height": image.height,
        "has_qr_matrix": points is not None,
        "payload_length": len(decoded_text) if decoded_text else 0
    }
    
    return decoded_text.strip() if decoded_text else None, metadata

def analyze_qr_payload(payload: str) -> List[IndicatorResult]:
    """
    Analyzes the decoded QR payload for fraud / deceptive payment patterns.
    """
    indicators: List[IndicatorResult] = []
    
    # 1. Payment URI schemes (Quishing / QR payment interception)
    payment_schemes = [
        (r'^bitcoin:[a-zA-Z0-9]+', "Cryptocurrency (Bitcoin) Direct Transfer", 30),
        (r'^ethereum:[a-zA-Z0-9]+', "Cryptocurrency (Ethereum) Direct Transfer", 30),
        (r'^upi://pay\?', "UPI Payment Instant Debit Request", 25),
        (r'^solana:[a-zA-Z0-9]+', "Cryptocurrency (Solana) Direct Transfer", 30),
    ]
    
    for scheme_regex, desc, weight in payment_schemes:
        if re.search(scheme_regex, payload, re.IGNORECASE):
            indicators.append(
                IndicatorResult(
                    indicator_type="Direct Financial / Payment QR Payload",
                    value=payload[:40] + "...",
                    weight=weight,
                    evidence=f"QR code contains an embedded direct payment initiation protocol ({desc})."
                )
            )

    # 2. Deceptive application installation (APK, mobile configuration profile)
    if any(ext in payload.lower() for ext in ['.apk', '.mobileconfig', '.ipa', '.exe', '.bat']):
        indicators.append(
            IndicatorResult(
                indicator_type="Executable / Application Download in QR",
                value=payload,
                weight=40,
                evidence="QR code encodes a direct download link to an application or system configuration package."
            )
        )

    # 3. Wi-Fi network credential harvesting
    if payload.startswith("WIFI:"):
        indicators.append(
            IndicatorResult(
                indicator_type="Wi-Fi Credential Payload",
                value=payload[:30] + "...",
                weight=10,
                evidence="QR code configures a wireless network connection. Verify if this is an authentic authorized hotspot."
            )
        )

    return indicators
