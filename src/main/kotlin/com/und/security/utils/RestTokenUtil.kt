package com.und.security.utils

import com.und.common.utils.DateUtils
import com.und.common.utils.loggerFor
import com.und.security.model.UndUserDetails
import com.und.security.model.User
import com.und.security.model.redis.JWTKeys
import com.und.security.service.JWTKeyService
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.mobile.device.Device
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.stereotype.Component
import java.util.*

@Component
class RestTokenUtil {

    @Autowired
    lateinit private var dateUtils: DateUtils

    @Autowired
    lateinit private var keyResolver: KeyResolver

    @Autowired
    lateinit private var jwtKeyService: JWTKeyService

    @Value("\${security.expiration}")
    private var expiration: Long = 0


    /**
     * use this method when you just need to validate that token is valid, even if it has been removed from database
     */
    fun validateToken(token: String): Pair<UndUserDetails?, JWTKeys> {
        fun getClaimsFromToken(token: String): Claims {
            return Jwts.parser()
                    .setSigningKeyResolver(keyResolver)
                    .parseClaimsJws(token)
                    .body

        }

        fun buildUserDetails(claims: Claims, jwtDetails: JWTKeys): UndUserDetails? {
            val userId = claims[CLAIM_USER_ID].toString().toLong()
            return UndUserDetails(
                    id = userId,
                    clientId = claims.clientId?.toLong(),
                    authorities = claims.roles.map { role -> SimpleGrantedAuthority(role) },
                    secret = jwtDetails.secret,
                    username = jwtDetails.username,
                    password = jwtDetails.password
            )
        }

        val claims = getClaimsFromToken(token)
        val userId = claims.userId
        return if (userId != null) {
            val jwtDetails = getJwtIfExists(userId.toLong())
            val userDetails = buildUserDetails(claims, jwtDetails)
            if (!claims.isTokenExpired) Pair(userDetails, jwtDetails) else Pair(null, jwtDetails)
        } else Pair(null, JWTKeys())

    }


    /**
     * use this method when you need to validate that token is validas well as exists in database
     */
    fun validateTokenForKeyType(token: String, keyType: KEYTYPE): Pair<UndUserDetails?, JWTKeys> {
        val (user, jwtDetails) = validateToken(token)
        val matches: Boolean = when (keyType) {
            KEYTYPE.LOGIN -> jwtDetails.loginKey == token
            KEYTYPE.PASSWORD_RESET -> jwtDetails.pswrdRstKey == token
            KEYTYPE.REGISTRATION -> jwtDetails.emailRgstnKey == token
        }
        return if (user != null && matches) Pair(user, jwtDetails) else Pair(null, jwtDetails)

    }

    fun getJwtIfExists(userId: Long): JWTKeys {
        return jwtKeyService.getKeyIfExists(userId)
    }

    fun updateJwt(jwt: JWTKeys): JWTKeys {
        return jwtKeyService.updateJwt(jwt)
    }

    /**
     * used to generate a token for keytype options,
     * user object should have, id, secret, username and password present
     */
    fun generateJwtByUser(user: User, device: Device, keyType: KEYTYPE): JWTKeys {
        val userDetails = RestUserFactory.create(user)
        return generateJwtByUserDetails(userDetails, device, keyType)
    }

    /**
     * used to generate a token for keytype options,
     * userDetails object should have, id, secret, username and password present
     * tries to get jwt object from cache, and updates requested key type if it exists else makes a new entry
     */
    fun generateJwtByUserDetails(user: UndUserDetails, device: Device, keyType: KEYTYPE): JWTKeys {

        fun buildKey(): JWTKeys {
            return if (user.id != null) {
                val jwt = getJwtIfExists(user.id)
                with(jwt) {
                    userId = "${user.id}"
                    when (keyType) {
                        com.und.security.utils.KEYTYPE.LOGIN -> loginKey = generateToken(user, device)
                        com.und.security.utils.KEYTYPE.PASSWORD_RESET -> pswrdRstKey = generateToken(user, device)
                        com.und.security.utils.KEYTYPE.REGISTRATION -> emailRgstnKey = generateToken(user, device)
                    }
                    this.secret = user.secret
                    this.username = user.username
                    this.password = user.password!!
                }
                jwt
            } else JWTKeys()

        }

        val jwt = buildKey()
        jwtKeyService.save(jwt)
        return jwt
    }


    inline private fun generateToken(userDetails: UndUserDetails, device: Device): String {

        val audience = when {
            device.isNormal -> AUDIENCE_WEB
            device.isMobile -> AUDIENCE_MOBILE
            device.isTablet -> AUDIENCE_TABLET
            else -> AUDIENCE_UNKNOWN
        }

        val createdDate = dateUtils.now()

        val claims = mapOf(
                CLAIM_KEY_USERNAME to userDetails.username,
                CLAIM_KEY_AUDIENCE to audience,
                CLAIM_USER_ID to userDetails.id.toString(),
                CLAIM_CLIENT_ID to userDetails.clientId.toString(),
                CLAIM_ROLES to userDetails.authorities.map { auth -> auth.authority },
                CLAIM_KEY_CREATED to createdDate
        )

        val expirationDate = Date(createdDate.time + expiration * 1000)

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS512, userDetails.secret)
                .compact()
    }


    companion object {
        protected val logger = loggerFor(RestTokenUtil::class.java)
        private const val serialVersionUID = -3301605591108950415L

        internal val CLAIM_KEY_USERNAME = "sub"
        internal val CLAIM_KEY_AUDIENCE = "audience"
        internal val CLAIM_KEY_CREATED = "created"
        internal val CLAIM_KEY_EXPIRED = "exp"
        internal val CLAIM_ONE_TIME = "onetime"
        internal val CLAIM_ROLES = "roles"
        internal val CLAIM_CLIENT_ID = "clientId"
        internal val CLAIM_USER_ID = "userId"
        internal val AUDIENCE_UNKNOWN = "unknown"
        internal val AUDIENCE_WEB = "web"
        internal val AUDIENCE_MOBILE = "mobile"
        internal val AUDIENCE_TABLET = "tablet"
    }
}

enum class KEYTYPE {
    LOGIN, PASSWORD_RESET, REGISTRATION
}