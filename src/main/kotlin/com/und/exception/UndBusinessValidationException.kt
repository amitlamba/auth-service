package com.und.exception

import com.und.model.api.ValidationError

class UndBusinessValidationException (
        var error: ValidationError
) : Exception() {


}

