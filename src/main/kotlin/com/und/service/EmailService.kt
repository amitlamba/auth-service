package com.und.service

import com.und.common.utils.loggerFor
import com.und.model.ClientVerification
import com.und.security.model.Client
import com.und.security.model.EmailMessage
import com.und.security.model.User
import org.springframework.stereotype.Service

@Service
class EmailService {

    companion object {

        protected val logger = loggerFor(EmailService::class.java)
    }

    fun sendEmail(message: EmailMessage){
        //TODO implement send email through messaging
        logger.info("email being sent -------------")

        logger.info("from ${message.from}")
        logger.info("to ${message.to}")
        logger.info("subject ${message.subject}")
        logger.info("body ${message.body}")

        logger.info("email sent -------------")
    }



}