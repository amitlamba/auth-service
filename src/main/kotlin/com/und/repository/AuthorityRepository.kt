package com.und.repository

import com.und.security.model.Authority
import com.und.security.model.AuthorityName
import com.und.security.model.Client
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface AuthorityRepository : JpaRepository<Authority, Long> {
    fun findByName(name: AuthorityName): Authority?
}