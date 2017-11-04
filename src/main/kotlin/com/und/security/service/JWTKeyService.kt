package com.und.security.service

import com.und.security.model.redis.JWTKeys
import com.und.repository.JWTKeyRepository
import com.und.security.model.UndUserDetails
import com.und.security.model.User
import com.und.security.utils.KEYTYPE
import com.und.security.utils.RestTokenUtil
import com.und.security.utils.RestUserFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.mobile.device.Device
import org.springframework.stereotype.Service

@Service
class JWTKeyService {

    @Autowired
    lateinit var jwtKeyRepository: JWTKeyRepository


    fun updateJwt(jwt: JWTKeys): JWTKeys {
        //TODO fix updating only what is required
        return jwtKeyRepository.save(jwt)

    }


    fun getKeyIfExists(userId: Long): JWTKeys {
        val cacheKey = generateIdKey(userId)
        val jwtOption = jwtKeyRepository.findById(cacheKey)
        return if (jwtOption.isPresent) {
            jwtOption.get()
        } else {
            JWTKeys(secret = "")

        }


    }

    fun save(jwt: JWTKeys) {
        jwtKeyRepository.save(jwt)
    }

    private fun generateIdKey(userId: Long): String = "$userId"
}


