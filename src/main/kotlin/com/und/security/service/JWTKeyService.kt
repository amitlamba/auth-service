package com.und.security.service

import com.und.security.model.redis.UserCache
import com.und.repository.UserCacheRepository
import com.und.security.repository.UserRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

@Service
class JWTKeyService {

    @Autowired
    lateinit var userCacheRepository: UserCacheRepository

    @Autowired
    lateinit var userRepository: UserRepository


    fun updateJwt(jwt: UserCache): UserCache {
        //TODO fix updating only what is required
        return userCacheRepository.save(jwt)

    }


    fun getKeyIfExists(userId: Long): UserCache {
        val cacheKey = generateIdKey(userId)
        val jwtOption = userCacheRepository.findById(cacheKey)
        return if (!jwtOption.isPresent) {
            val jwtKeys =  UserCache(secret = "", userId = generateIdKey(userId))
            val user = userRepository.findById(userId)
            if(user.isPresent) {
                with(jwtKeys) {
                    this.userId = generateIdKey(userId)
                    this.secret = user.get().clientSecret
                    this.loginKey = user.get().key
                    this.username = user.get().username
                    this.password = user.get().password
                    this.email = user.get().email
                    this.clientId = "${user.get().client?.id?:-1}"
                }
            }
            save(jwtKeys)
            jwtKeys

        } else {
            jwtOption.get()
        }


    }

    fun save(jwt: UserCache) {
        userCacheRepository.save(jwt)
    }

    private fun generateIdKey(userId: Long): String = "$userId"
}


