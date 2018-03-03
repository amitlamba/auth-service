package com.und.security.controller

import com.und.model.api.Data
import com.und.model.api.Response
import com.und.model.api.ResponseStatus
import com.und.security.model.RestAuthenticationRequest
import com.und.security.model.UndUserDetails
import com.und.security.service.SecurityAuthenticationResponse
import com.und.security.utils.KEYTYPE
import com.und.security.utils.RestTokenUtil
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.mobile.device.Device
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.web.bind.annotation.*

@CrossOrigin
@RestController
class AuthenticationRestController {


    @Autowired
    lateinit private var authenticationManager: AuthenticationManager

    @Autowired
    lateinit private var userDetailsService: UserDetailsService

    @Autowired
    lateinit private var restTokenUtil: RestTokenUtil

    @RequestMapping(value = "\${security.route.authentication.path}", method = arrayOf(RequestMethod.POST))
    @Throws(AuthenticationException::class)
    fun createAuthenticationToken(@RequestBody authenticationRequest: RestAuthenticationRequest, device: Device): ResponseEntity<*> {

        fun generateJwtByUser(username: String, device: Device): String {
            // Reload password post-security so we can generate token
            val user: UndUserDetails? = userDetailsService.loadUserByUsername(username) as UndUserDetails
            return if (user != null) {
                restTokenUtil.generateJwtByUserDetails(user, device, KEYTYPE.LOGIN).loginKey ?: ""
            } else ""
        }

        return try {
            val authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken(
                            authenticationRequest.username,
                            authenticationRequest.password
                    )
            )
            SecurityContextHolder.getContext().authentication = authentication
            val token = generateJwtByUser(authenticationRequest.username ?: "", device)
            ResponseEntity.ok(
                    Response(
                            status = ResponseStatus.SUCCESS,
                            data = Data(SecurityAuthenticationResponse(token))
                    )
            )
        } catch (exception: AuthenticationException) {
            ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Response(
                    status = ResponseStatus.FAIL,
                    message = "Invalid Username/Password"
            ))
        }


    }

    @RequestMapping(value = "\${security.route.authentication.path}/validate/{authToken}", method = arrayOf(RequestMethod.GET))
    @Throws(AuthenticationException::class)
    fun authenticationToken(@PathVariable("authToken") authToken: String, device: Device): ResponseEntity<*> {

        val (userDetails, jwtToken) = restTokenUtil.validateTokenForKeyType(authToken, KEYTYPE.LOGIN)
        return if (userDetails?.id != null) {
            ResponseEntity.ok(Response(
                    status = ResponseStatus.SUCCESS,
                    data = Data(userDetails)

            ))
        } else {
            ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Response(
                    status = ResponseStatus.FAIL,
                    message = "Invalid Authentication Attempt"
            ))
        }

    }


    @RequestMapping(value = "\${security.route.authentication.path}/userdetail/{name}", method = arrayOf(RequestMethod.GET))
    @Throws(AuthenticationException::class)
    fun userByName(@PathVariable("name") name: String, device: Device): ResponseEntity<*> {
        //FIXME check for authentication token of service in header
        val userDetails = userDetailsService.loadUserByUsername(name)
        return if (userDetails?.username != null) {
            ResponseEntity.ok(Response(
                    status = ResponseStatus.SUCCESS,
                    data = Data(userDetails)

            ))
        } else {
            ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Response(
                    status = ResponseStatus.FAIL,
                    message = "Invalid Authentication Attempt"
            ))
        }

    }


}
