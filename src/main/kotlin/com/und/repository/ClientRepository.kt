package com.und.repository

import com.und.security.model.Client
import com.und.security.model.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface ClientRepository : JpaRepository<Client, Long> {
    fun findByName(name: String): Client?
    fun findByEmail(email: String): Client?
}
