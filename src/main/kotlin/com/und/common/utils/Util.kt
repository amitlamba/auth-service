package com.und.common.utils

import com.und.security.model.AuthorityName
import com.und.security.service.AuthorityService
import com.und.security.utils.AuthenticationUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory


//FIXME add extensions for logger and try to use idiomatic property delegates
fun <T> loggerFor(clazz: Class<T>) = LoggerFactory.getLogger(clazz)

fun Logger.debugT(msg: String) = if (isDebugEnabled) this.debug(msg) else Unit

fun usernameFromEmailAndType(email: String, userType: Int) = when (userType) {
    AuthenticationUtils.USER_TYPE_ADMIN -> email
    AuthenticationUtils.USER_TYPE_EVENT -> "event_$email"
    else -> throw Exception("invalid user type")
}

fun AuthorityService.authorityByType(userType: Int) = when (userType) {
    1 -> this.findByName(AuthorityName.ROLE_ADMIN)

    2 -> this.findByName(AuthorityName.ROLE_EVENT)
    else -> throw Exception("invalid user type")
}

