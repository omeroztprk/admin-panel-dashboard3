const nodemailer = require('nodemailer');
const config = require('../config');
const logger = require('../utils/logger');
const { t: globalT } = require('../config/i18n');

let transporter = null;

const initializeEmailService = () => {
  if (!config.email.enabled) {
    if (config.env === 'development') {
      logger.info('Email service disabled');
    }
    return null;
  }

  try {
    transporter = nodemailer.createTransport({
      service: config.email.service,
      host: config.email.host,
      port: config.email.port,
      secure: config.email.secure,
      auth: {
        user: config.email.user,
        pass: config.email.pass
      },
      pool: true,
      maxConnections: 5,
      maxMessages: 100
    });

    if (config.env === 'development') {
      logger.info('Email service initialized successfully');
    }
    return transporter;
  } catch (error) {
    logger.error('Failed to initialize email service:', error);
    return null;
  }
};

const sendEmail = async (to, subject, html, language = 'en') => {
  if (!transporter) {
    logger.warn('Email service not initialized');
    return false;
  }

  try {
    const mailOptions = {
      from: `"${globalT('email.from_name', { lng: language })}" <${config.email.from}>`,
      to,
      subject,
      html
    };

    const info = await transporter.sendMail(mailOptions);
    
    if (config.env === 'development' && config.i18n.debug) {
      logger.debug(`Email sent successfully to ${to}`, { messageId: info.messageId });
    }
    return true;
  } catch (error) {
    logger.error('Failed to send email:', { error: error.message, to, subject });
    return false;
  }
};

const sendTfaCode = async (email, code, language = 'en') => {
  const subject = globalT('email.tfa.subject', { lng: language });
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <h2 style="color: #333; text-align: center; margin-bottom: 30px;">
        ${globalT('email.tfa.title', { lng: language })}
      </h2>
      
      <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
        <p style="color: #555; font-size: 16px; line-height: 1.5; margin: 0;">
          ${globalT('email.tfa.message', { lng: language })}
        </p>
      </div>
      
      <div style="text-align: center; margin: 30px 0;">
        <div style="background-color: #007bff; color: white; font-size: 24px; font-weight: bold; 
                    padding: 15px 30px; border-radius: 8px; display: inline-block; letter-spacing: 3px;">
          ${code}
        </div>
      </div>
      
      <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 15px; margin: 20px 0;">
        <p style="color: #856404; font-size: 14px; margin: 0;">
          <strong>${globalT('email.tfa.warning_title', { lng: language })}:</strong>
          ${globalT('email.tfa.warning_message', { lng: language })}
        </p>
      </div>
      
      <p style="color: #666; font-size: 14px; text-align: center; margin-top: 30px;">
        ${globalT('email.tfa.footer', { lng: language })}
      </p>
    </div>
  `;

  return sendEmail(email, subject, html, language);
};

const verifyEmailService = async () => {
  if (!transporter) return false;
  
  try {
    await transporter.verify();
    if (config.env === 'development' && config.i18n.debug) {
      logger.debug('Email service verification successful');
    }
    return true;
  } catch (error) {
    logger.error('Email service verification failed:', error);
    return false;
  }
};

module.exports = {
  initializeEmailService,
  sendEmail,
  sendTfaCode,
  verifyEmailService
};