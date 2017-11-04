package com.und.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories
import org.springframework.data.redis.connection.RedisConnectionFactory



@Configuration
@EnableRedisRepositories
class RedisConfig {

    @Bean
    fun connectionFactory(): RedisConnectionFactory {
        return JedisConnectionFactory()
    }

    @Bean
    fun redisTemplate(): RedisTemplate<*, *> {

        val template =  RedisTemplate<ByteArray, ByteArray>()
        template.connectionFactory = connectionFactory()
        return template
    }
}