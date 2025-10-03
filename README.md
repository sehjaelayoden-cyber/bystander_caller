# Hospital Management System

A web-based hospital management system that allows doctors to manage patient companions and communicate with them through voice calls using Twilio integration.

## Features

- Doctor authentication system
- QR code scanning for companion registration
- Companion management (add/remove)
- Voice call integration using Twilio
- Blue-themed modern UI
- Real-time companion list updates
- Secure data management

## Setup Instructions

1. Create a virtual environment and activate it:
```bash
python -m venv venv
.\venv\Scripts\activate
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the root directory with your Twilio credentials:
```
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_PHONE_NUMBER=your_twilio_phone_number
```

4. Initialize the database:
```bash
python
>>> from app import app, db
>>> with app.app_context():
...     db.create_all()
```

5. Run the application:
```bash
python app.py
```

## Using the System

1. Access the application at `http://localhost:5000`
2. Login with your doctor credentials
3. Use the dashboard to:
   - View all registered companions
   - Add new companions (manually or via QR code)
   - Make voice calls to companions
   - Remove companions after patient checkout

## QR Code Generation

To generate QR codes for companions:
1. Use the `qr_generator.py` script
2. Modify the sample data as needed
3. Generated QR codes will be saved in the `static/qr_codes` directory

## Security Notes

- Keep your `.env` file secure and never commit it to version control
- Regularly update your dependencies
- Use strong passwords for doctor accounts
- Monitor Twilio usage for any unusual activity

## Technical Details

- Built with Flask framework
- SQLite database for data storage
- Twilio API for voice calls
- HTML5 QR Code scanner for companion registration
- Bootstrap 5 for responsive UI
- Blue theme implementation

## License & Attribution

This project is distributed under the Apache License 2.0. See the LICENSE file for the full text and the SPDX identifiers present at the top of each source file for per-file notices.

If you reuse or publish work based on this codebase, please attribute Ikhlas as the 2025 copyright holder.
