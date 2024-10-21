import { Injectable } from '@nestjs/common';
import * as sgMail from '@sendgrid/mail';

@Injectable()
export class EmailService {
  constructor() {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  }
  async sendEmail(receiverEmail: string, otp: string): Promise<void> {
    const msg = {
      to: receiverEmail,
      from: 'ruadennhos3@gmail.com',
      subject: 'Please See your OTP',
      text: `Your OTP code is: ${otp}`,
      html: `<p>Your OTP code is: <strong>${otp}</strong></p>`,
    };

    try {
      await sgMail.send(msg);
      console.log('Email sent successfully');
    } catch (error) {
      console.error('Error sending email:', error);

      if (error.response) {
        console.error('Error response:', error.response.body);
      }
    }
  }
}
