package com.und.controller

import com.und.common.utils.loggerFor
import com.und.exception.UndBusinessValidationException
import com.und.model.api.Data
import com.und.model.api.Response
import com.und.model.api.ResponseStatus
import com.und.model.ui.PasswordRequest
import com.und.model.ui.RegistrationRequest
import com.und.model.utils.Email
import com.und.security.model.EmailMessage
import com.und.security.service.UserService
import com.und.security.utils.KEYTYPE
import com.und.security.utils.RestTokenUtil
import com.und.service.EmailService
import com.und.service.RegistrationService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import javax.mail.internet.InternetAddress
import javax.validation.Valid

@CrossOrigin
@RestController
@RequestMapping("/register")
class RegisterController {

    companion object {

        protected val logger = loggerFor(RegisterController::class.java)
    }

    @Autowired
    lateinit var registrationService: RegistrationService

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit var emailService: EmailService

    @Autowired
    lateinit var restTokenUtil: RestTokenUtil

    @GetMapping
    fun registerForm() {

    }

    @PostMapping
    fun register(@Valid @RequestBody request: RegistrationRequest) {
        val errors = registrationService.validate(request)
        if (errors.getFieldErrors().isNotEmpty()) {
            logger.error("business validation failure while registering ${request.email} , with errors ${errors.getFieldErrors()}")
            throw  UndBusinessValidationException(errors)
        }
        val client = registrationService.register(request)
        registrationService.sendVerificationEmail(client)
    }

    @GetMapping(value = ["/verifyemail/{email:.+}/{code}"])
    fun verifyEmail(@PathVariable email: String, @PathVariable code: String) {
        registrationService.verifyEmail(email, code)

    }

    @GetMapping(value = ["/sendvfnmail/{email:.+}"])
    fun newverifyEmail(@PathVariable email: String) {
        registrationService.sendReVerificationEmail(email)

    }

    @GetMapping(value = ["/forgotpassword/{email:.+}"])
    fun forgotPassword(@PathVariable email: String): ResponseEntity<Response> {
        val code = userService.generateJwtForForgotPassword(email)
        emailService.sendEmail(Email(
                clientID = 1,
                fromEmailAddress = InternetAddress("admin@userndot.com", "UserNDot Admin"),
                toEmailAddresses = arrayOf(InternetAddress(email)),
                emailBody = """
                    Hi, $//userName
                    please click http://localhost:8080/register/resetpassword/$email/${code.pswrdRstKey} to reset password
                """.trimIndent(),
                emailSubject = "forgot password"

        ))
        return if (code.pswrdRstKey.isNullOrBlank()) {
            ResponseEntity.status(HttpStatus.NOT_FOUND).body(Response(
                    message = "Invalid Email Id",
                    status = com.und.model.api.ResponseStatus.FAIL
            ))
        } else {
            ResponseEntity.ok().body(Response(
                    message = "Invalid Link",
                    status = ResponseStatus.SUCCESS
            ))
        }
    }

    @GetMapping(value = ["/resetpassword/{code}"])
    fun resetPasswordForm(@PathVariable code: String): ResponseEntity<Response> {
        val (userDetails, jwtToken) = restTokenUtil.validateTokenForKeyType(code, KEYTYPE.PASSWORD_RESET)
        return if (userDetails == null || jwtToken.pswrdRstKey != code) {
            ResponseEntity.status(HttpStatus.NOT_FOUND).body(Response(
                    message = "Invalid Link",
                    status = ResponseStatus.FAIL
            ))
        } else {
            ResponseEntity.status(HttpStatus.OK).body(Response(
                    status = ResponseStatus.SUCCESS,
                    data = Data(
                            value = PasswordRequest(password = ""),
                            message = "Enter password To Reset"
                    )
            ))
        }
    }

    @PostMapping(value = ["/resetpassword/{code}"])
    fun resetPassword(@PathVariable code: String,
                      @RequestBody @Valid passwordRequest: PasswordRequest): ResponseEntity<Response> {

        val (userDetails, jwtToken) = restTokenUtil.validateTokenForKeyType(code, KEYTYPE.PASSWORD_RESET)
        return if (userDetails == null || jwtToken.pswrdRstKey != code) {
            ResponseEntity.status(HttpStatus.NOT_FOUND).body(Response(
                    message = "Invalid Link",
                    status = ResponseStatus.FAIL
            ))
        } else {
            userService.resetPassword(userDetails, passwordRequest.password)
            ResponseEntity.ok().body(Response(
                    status = ResponseStatus.SUCCESS,
                    message = "Password successfully changed"
            )
            )
        }
    }


}