package com.und.controller

import com.und.common.utils.loggerFor
import com.und.model.api.Data
import com.und.model.api.Response
import com.und.model.api.ResponseStatus
import com.und.model.ui.PasswordRequest
import com.und.model.ui.UserProfileRequest
import com.und.security.model.Client
import com.und.security.service.ClientService
import com.und.security.service.JWTKeyService
import com.und.security.service.UserService
import com.und.security.utils.AuthenticationUtils
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.ResponseEntity
import org.springframework.mobile.device.Device
import org.springframework.web.bind.annotation.*
import javax.validation.Valid

@CrossOrigin(origins= arrayOf("*"), maxAge = 3600)
@RestController
@RequestMapping("/setting")
class UserProfileController {

    companion object {

        protected val logger = loggerFor(UserProfileController::class.java)
    }

    @Autowired
    lateinit var userService: UserService

    @Autowired
    lateinit private var jwtKeyService: JWTKeyService

    @Autowired
    lateinit var clientService: ClientService


    @RequestMapping(value = "/resetpassword", method = arrayOf(RequestMethod.POST))
    fun resetPassword(@RequestBody @Valid passwordRequest: PasswordRequest): ResponseEntity<Response> {
        val userDetails = AuthenticationUtils.principal

        userService.resetPassword(userDetails, passwordRequest.password)
        return ResponseEntity.ok().body(Response(
                status = ResponseStatus.SUCCESS,
                message = "Password successfully changed"
        ))
    }


    @RequestMapping(value = "/userDetails", method = arrayOf(RequestMethod.GET))
    fun userDetails(): ResponseEntity<Response> {
        val clientId = AuthenticationUtils.clientID
        return if (clientId != null) {
            val client = clientService.findById(clientId)
            val userProfile = UserProfileRequest(
                    firstname = client.firstname ?: "",
                    lastname = client.lastname ?: "",
                    address = client.address,
                    phone = client.phone,
                    eventUserToken = client.users.filter { it.userType == 2 }.first().key ?: ""

            )

            ResponseEntity.ok().body(Response(
                    status = ResponseStatus.SUCCESS,
                    data = Data(userProfile)
            ))
        } else {
            ResponseEntity.badRequest().body(Response(
                    status = ResponseStatus.ERROR,
                    message = "not a valid login"
            ))
        }
    }

    @RequestMapping(value = "/updateUserDetails", method = arrayOf(RequestMethod.POST))
    fun updateUserDetails(@Valid @RequestBody request: UserProfileRequest): ResponseEntity<Response> {
        val client = Client()
        with(client) {
            id = AuthenticationUtils.clientID
            firstname = request.firstname
            lastname = request.lastname
            address = request.address
            phone = request.phone
        }
        val status = clientService.updateClient(client)
        return if (status) ResponseEntity.ok().body(Response()) else ResponseEntity.badRequest().body(Response())
    }


    @RequestMapping(value = "/refreshToken", method = arrayOf(RequestMethod.POST))
    fun generateToken(device: Device): ResponseEntity<*> {
        val user = AuthenticationUtils.principal
        val jwt = userService.updateJwtOfEventUser(device, user)
        return ResponseEntity.ok(jwt)
    }

}