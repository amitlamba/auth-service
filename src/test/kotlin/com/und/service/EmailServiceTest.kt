package com.und.service

import com.und.model.utils.Email
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit4.SpringRunner
import javax.mail.internet.InternetAddress

@RunWith(SpringRunner::class)
@SpringBootTest
@Ignore
class EmailServiceTest {

    @Autowired
    private lateinit var emailService: EmailService

    @Test
    fun sendEmailTest() {
        emailService.sendEmail(
                Email(
                        clientID = 1,
                        fromEmailAddress = InternetAddress("amit@userndot.com", "UserNDot Admin"),
                        toEmailAddresses = arrayOf(InternetAddress("amitlamba4198@gmail.com")),
                        emailBody = """
                    Hi, $//userName
                    please click http://localhost:8080/register/resetpassword/amitlamba4198@gmail.com/this-is-the-code to reset password
                """.trimIndent(),
                        emailSubject = "forgot password")
        )
    }
}