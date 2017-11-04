package com.und.security.model

class EmailMessage(
        val from: String,
        val to: String,
        var subject: String = "",
        var body: String = ""

)