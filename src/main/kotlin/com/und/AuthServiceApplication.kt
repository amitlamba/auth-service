package com.und


import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.cloud.context.config.annotation.RefreshScope
import org.springframework.cloud.netflix.eureka.EnableEurekaClient
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.support.ResourceBundleMessageSource

@SpringBootApplication
@EnableAutoConfiguration
@ComponentScan(basePackages = arrayOf("com.und"))
@RefreshScope
@EnableEurekaClient
class AuthServiceApplication

    fun main(args: Array<String>) {

        SpringApplication.run(AuthServiceApplication::class.java, *args)
    }

