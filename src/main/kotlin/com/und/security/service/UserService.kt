package com.und.security.service

import com.und.common.utils.usernameFromEmailAndType
import com.und.security.model.UndUserDetails
import com.und.security.model.User
import com.und.security.model.redis.UserCache
import com.und.security.repository.UserRepository
import com.und.security.utils.KEYTYPE
import com.und.security.utils.RestTokenUtil
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.mobile.device.Device
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional


@Service
@Transactional
class UserService {

    @Autowired
    lateinit var userRepository: UserRepository

    @Autowired
    lateinit private var restTokenUtil: RestTokenUtil

    @Autowired
    lateinit var passwordEncoder: PasswordEncoder

    fun findByUsername(username: String): User? {
        return userRepository.findByUsername(username)

    }

    fun updateJwtOfEventUser( adminUser: UndUserDetails): Int {
        //FIXME usernameFromEmailAndType method need fix and not required here
        val username = usernameFromEmailAndType(adminUser.username, 2)
        val jwt = generateJwtLogin(username)
        val updatedCount = userRepository.updateJwtOfEventUser(jwt.loginKey?:"", username)
        restTokenUtil.updateJwt(jwt)
        return updatedCount

    }




    fun resetPassword(userDetails: UndUserDetails, password:String) {
        fun resetKeys(jwtToken: UserCache) {

            jwtToken.pswrdRstKey = null
            jwtToken.loginKey = null
            restTokenUtil.updateJwt(jwtToken)
        }

        val userId = userDetails.id
        if(userId!=null) {
            userRepository.resetPassword(passwordEncoder.encode(password),
                    userDetails.username)
            val jwtToken = restTokenUtil.getJwtIfExists(userId)
            resetKeys(jwtToken)
        }
    }

    fun generateJwtForForgotPassword(email: String): UserCache {
        return generateJwtLogin(email, KEYTYPE.PASSWORD_RESET)
    }

    private fun generateJwtLogin(username: String): UserCache {
        return generateJwtLogin(username, KEYTYPE.LOGIN)
    }

    private fun generateJwtLogin(username: String, keytype: KEYTYPE): UserCache {
        // Reload password post-security so we can generate token
        val user = findByUsername(username)
        return if (user != null) {
            restTokenUtil.generateJwtByUser(user, keytype)
        } else UserCache()
    }
}