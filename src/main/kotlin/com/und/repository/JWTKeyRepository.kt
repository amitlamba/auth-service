package com.und.repository

import com.und.security.model.redis.JWTKeys
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Repository
interface JWTKeyRepository : CrudRepository<JWTKeys, String>{
}