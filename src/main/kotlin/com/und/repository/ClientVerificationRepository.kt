package com.und.repository

import com.und.model.ClientVerification
import com.und.security.model.Client
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface ClientVerificationRepository : JpaRepository<ClientVerification, Long> {
    fun findByEmailCodeAndClient(code: String, clientId: Long?): ClientVerification?
    //fun findByClientId(name: String): ClientVerification?
}