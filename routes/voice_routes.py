# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 ASHMIL

from flask import Blueprint, request, url_for, jsonify
from flask_login import login_required, current_user
from utils.twilio_utils import TwilioHandler
from models import db, Patient, CallLog

voice_bp = Blueprint('voice', __name__)
twilio_handler = TwilioHandler()


@voice_bp.route('/voice-message')
def voice_message():
    """Generate TwiML for voice message"""
    message = request.args.get('message', 'Hello, this is a call from the hospital.')
    return twilio_handler.generate_twiml_response(message)


@voice_bp.route('/status-callback', methods=['POST'])
def call_status_callback():
    """Handle Twilio call status callbacks"""
    call_sid = request.form.get('CallSid')
    call_status = request.form.get('CallStatus')
    duration = request.form.get('CallDuration', 0)

    # Update call log with status
    call_log = CallLog.query.filter_by(call_sid=call_sid).first()
    if call_log:
        call_log.status = call_status
        call_log.duration = int(duration)
        db.session.commit()

    return jsonify({'status': 'success'})


@voice_bp.route('/make-call', methods=['POST'])
@login_required
def make_call():
    """Initiate outbound call to patient's bystander"""
    try:
        data = request.get_json()
        patient_id = data.get('patient_id')

        if not patient_id:
            return jsonify({'status': 'error', 'message': 'Patient ID is required'})

        patient = Patient.query.get(patient_id)
        if not patient:
            return jsonify({'status': 'error', 'message': 'Patient not found'})

        # Get or use default message
        voice_message = current_user.voice_message or "Hello, this is a call from the hospital."

        # Create callback URL for voice message
        callback_url = url_for('voice.voice_message',
                               message=voice_message,
                               _external=True)

        # Create call log entry
        call_log = CallLog(
            doctor_id=current_user.id,
            patient_id=patient.id,
            phone_number=patient.phone_number,
            status='initiated'
        )
        db.session.add(call_log)
        db.session.commit()

        # Make the call
        call_sid = twilio_handler.make_outbound_call(
            to_number=patient.phone_number,
            message=voice_message,
            callback_url=callback_url
        )

        if call_sid:
            call_log.call_sid = call_sid
            db.session.commit()
            return jsonify({
                'status': 'success',
                'message': 'Call initiated successfully',
                'call_sid': call_sid
            })
        else:
            call_log.status = 'failed'
            db.session.commit()
            return jsonify({
                'status': 'error',
                'message': 'Failed to initiate call'
            })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })
