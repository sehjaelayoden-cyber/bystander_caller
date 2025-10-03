# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Ikhlas

from twilio.rest import Client
from twilio.twiml.voice_response import VoiceResponse
import os
from typing import Optional


class TwilioHandler:
    def __init__(self):
        self.account_sid = os.getenv('TWILIO_ACCOUNT_SID')
        self.auth_token = os.getenv('TWILIO_AUTH_TOKEN')
        self.twilio_number = os.getenv('TWILIO_PHONE_NUMBER')
        self.client = Client(self.account_sid, self.auth_token)

    def generate_twiml_response(self, message: str) -> str:
        """Generate TwiML response for voice message"""
        response = VoiceResponse()
        response.pause(length=1)
        response.say(message, voice='alice', language='en-US')
        return str(response)

    def make_outbound_call(self,
                           to_number: str,
                           message: str,
                           callback_url: str) -> Optional[str]:
        """
        Make an outbound call to a patient's bystander

        Args:
            to_number: The phone number to call
            message: The message to deliver
            callback_url: URL for TwiML response

        Returns:
            str: Call SID if successful, None if failed
        """
        try:
            call = self.client.calls.create(
                to=to_number,
                from_=self.twilio_number,
                url=callback_url,
                method='POST',
                status_callback=callback_url,
                status_callback_event=['initiated', 'ringing', 'answered', 'completed']
            )
            return call.sid
        except Exception as e:
            print(f"Error making outbound call: {str(e)}")
            return None