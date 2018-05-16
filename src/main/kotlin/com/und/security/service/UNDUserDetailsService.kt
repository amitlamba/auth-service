package com.und.security.service

import com.und.repository.UserCacheRepository
import com.und.security.utils.RestUserFactory
import com.und.security.repository.UserRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

/**
 * Created by shiv on 21/07/17.
 */
@Service
class UNDUserDetailsService : UserDetailsService {

    @Autowired
    private lateinit var userRepository: UserRepository

    @Autowired
    private lateinit var userCacheRepository: UserCacheRepository

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails {
        //userCacheRepository.findByUserName()
        val user = userRepository.findByUsername(username)

        return if (user == null) {
            throw UsernameNotFoundException(String.format("No user found with username '%s'.", username))
        } else {
            RestUserFactory.create(user)
        }
    }
}
