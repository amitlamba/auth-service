package com.und.security

import com.nhaarman.mockito_kotlin.whenever
import com.und.common.utils.DateUtils
import com.und.repository.JWTKeyRepository
import com.und.security.model.AuthorityName
import com.und.security.model.UndUserDetails
import com.und.security.model.redis.JWTKeys
import com.und.security.service.JWTKeyService
import com.und.security.utils.KEYTYPE
import com.und.security.utils.KeyResolver
import com.und.security.utils.RestTokenUtil
import io.jsonwebtoken.Claims
import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.impl.TextCodec
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.util.DateUtil
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.ArgumentMatchers
import org.mockito.InjectMocks
import org.mockito.Mock
import org.mockito.Mockito.`when`
import org.mockito.MockitoAnnotations
import org.mockito.junit.MockitoJUnitRunner
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.test.util.ReflectionTestUtils
import java.util.*

/**
 * Created by shiv on 21/07/17.
 */
@RunWith(MockitoJUnitRunner::class)
class RestTokenUtilTest {

    @Mock
    lateinit private var dateUtilsMock: DateUtils

    @InjectMocks
    lateinit private var keyResolverMock: KeyResolver

    @InjectMocks
    lateinit private var restTokenUtil: RestTokenUtil

    @Mock
    lateinit private var jwtKeyService: JWTKeyService


    private val secret: String = "supremeSecret"

    @Before
    fun init() {
        MockitoAnnotations.initMocks(this)
        ReflectionTestUtils.setField(restTokenUtil, "expiration", 3600L) // one hour
        ReflectionTestUtils.setField(restTokenUtil, "keyResolver", keyResolverMock)
        //ReflectionTestUtils.setField(restTokenUtil, "jwtKeyService", jwtKeyService)
/*        whenever(
                keyResolverMock.resolveSigningKeyBytes(ArgumentMatchers.any<DefaultJwsHeader>(), ArgumentMatchers.any<Claims?>())).
                thenReturn(TextCodec.BASE64.decode(secret)
                )*/
    }

    @Test
    @Throws(Exception::class)
    fun testGenerateTokenGeneratesDifferentTokensForDifferentCreationDates() {
        `when`(dateUtilsMock.now())
                .thenReturn(DateUtil.yesterday())
                .thenReturn(DateUtil.now())

        val token = createToken()
        val laterToken = createToken()

        assertThat(token).isNotEqualTo(laterToken)
    }

    @Test
    @Throws(Exception::class)
    fun getUsernameFromToken() {
        `when`(dateUtilsMock.now()).thenReturn(DateUtil.now())

        val token = createToken()
        val (user, jwtKey) = restTokenUtil.validateToken(token)
        assertThat(user?.username).isEqualTo(TEST_USER)
    }


    @Test
    @Throws(Exception::class)
    fun getRolesFromToken() {
        `when`(dateUtilsMock.now()).thenReturn(DateUtil.now())
        val token = createToken()
        val (user, jwtKey) = restTokenUtil.validateToken(token)

        assertThat(user?.authorities).isEqualTo(
                arrayListOf(
                        SimpleGrantedAuthority(AuthorityName.ROLE_ADMIN.name),
                        SimpleGrantedAuthority(AuthorityName.ROLE_EVENT.name)
                )
        )
    }

    // TODO write tests
    //
    //    @Test
    //    public void validateToken() throws Exception {
    //    }

    private fun createClaims(creationDate: String): Map<String, Any> {
        val claims = HashMap<String, Any>()
        claims.put(RestTokenUtil.CLAIM_KEY_USERNAME, TEST_USER)
        claims.put(RestTokenUtil.CLAIM_KEY_AUDIENCE, "testAudience")
        claims.put(RestTokenUtil.CLAIM_KEY_CREATED, DateUtil.parseDatetime(creationDate))
        claims.put(RestTokenUtil.CLAIM_ROLES, arrayListOf(SimpleGrantedAuthority(AuthorityName.ROLE_ADMIN.name)))
        return claims
    }

    private fun createToken(): String {
        val user = UndUserDetails(
                id = 1L,
                username = TEST_USER,
                secret = TextCodec.BASE64.encode(secret),
                key = "key",
                password = "password",
                clientId = 1,
                authorities = arrayListOf(SimpleGrantedAuthority(AuthorityName.ROLE_ADMIN.name), SimpleGrantedAuthority(AuthorityName.ROLE_EVENT.name))
        )
        val jwtKey = JWTKeys(secret = secret)
        with(jwtKey) {
            username = user.username
            secret = user.secret
            password = user.password ?: ""

        }
        val device = DeviceMock()
        device.isNormal = true
        `when`(restTokenUtil.getJwtIfExists(user.id!!))
                .thenReturn(jwtKey)

        val jwtKeys = restTokenUtil.generateJwtByUserDetails(user, device, KEYTYPE.LOGIN)
        return jwtKeys.loginKey ?: ""
    }

    companion object {

        private val TEST_USER = "testUser"
    }

}