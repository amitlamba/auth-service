package com.und.model.api

import com.und.model.api.FieldError
import java.util.ArrayList


class ValidationError {

    private val fieldErrors = ArrayList<FieldError>()

    fun addFieldError(path: String, message: String) {
        val error = FieldError(path, message)
        fieldErrors.add(error)
    }

    fun getFieldErrors(): List<FieldError> {
        return fieldErrors
    }
}
