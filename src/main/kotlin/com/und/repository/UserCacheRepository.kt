package com.und.repository

import com.und.security.model.redis.UserCache
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Repository
interface UserCacheRepository : CrudRepository<UserCache, String>{
}