package com.und.security.service

import com.und.repository.AuthorityRepository
import com.und.security.model.Authority
import com.und.security.model.AuthorityName
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service

@Service
class AuthorityService {
    @Autowired
    lateinit var authorityRepository: AuthorityRepository

    fun findByName(name: AuthorityName): Authority? {
        return authorityRepository.findByName(name)
    }
}

