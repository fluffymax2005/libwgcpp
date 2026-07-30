#include "wgexception.h"

WgException::WgException(const std::string& message, int error_code)
    : std::runtime_error(message + ". Error code = " + std::to_string(error_code))
    , code{error_code} {
}

const char* WgException::what() const noexcept {
    return std::runtime_error::what();
}

int WgException::getCode() const noexcept {
    return code;
}


