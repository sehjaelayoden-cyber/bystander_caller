# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Ikhlas

import qrcode
import json
import os

def generate_companion_qr(data, output_dir='static/qr_codes'):
    """
    Generate a QR code for companion data
    
    Args:
        data (dict): Dictionary containing companion information
        output_dir (str): Directory to save the QR code image
    
    Returns:
        str: Path to the generated QR code image
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    # Convert data to JSON string
    json_data = json.dumps(data)
    
    # Create QR code instance
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    
    # Add data
    qr.add_data(json_data)
    qr.make(fit=True)
    
    # Create an image from the QR Code
    qr_image = qr.make_image(fill_color="black", back_color="white")
    
    # Save the image
    filename = f"companion_{data['patient_id']}.png"
    filepath = os.path.join(output_dir, filename)
    qr_image.save(filepath)
    
    return filepath

if __name__ == "__main__":
    # Example usage
    sample_data = {
        "name": "John Doe",
        "phone": "+1234567890",
        "patient_name": "Jane Doe",
        "patient_id": "P12345"
    }
    
    qr_path = generate_companion_qr(sample_data)
    print(f"QR code generated at: {qr_path}")
