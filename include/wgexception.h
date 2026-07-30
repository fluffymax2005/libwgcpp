#ifndef WGEXCEPTION_H
#define WGEXCEPTION_H

#include <stdexcept>

class WgException : public std::runtime_error {
public:
    WgException(const std::string& message, int error_code);
    virtual const char* what() const noexcept override;

    int getCode() const noexcept;
protected:
    int code;
};

#endif // WGEXCEPTION_H
