package com.und.security.utils


import com.und.security.model.Authority
import com.und.security.model.UndUserDetails
import com.und.security.model.User
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority

class RestUserFactory {
    companion object {

        @JvmStatic
        fun create(user: User) =
                UndUserDetails(
                        id = user.id,
                        clientId = user.client?.id,
                        username = user.username,
                        firstname = user.firstname,
                        lastname = user.lastname,
                        email = user.email,
                        password = user.password,
                        authorities = mapToGrantedAuthorities(user.authorities),
                        enabled = user.enabled,
                        secret = user.clientSecret,
                        key = user.key,
                        userType = user.userType
                )

        private fun mapToGrantedAuthorities(authorities: List<Authority>): List<GrantedAuthority> {
            return authorities.map { authority -> SimpleGrantedAuthority(authority.name.name) }

        }
    }
}
