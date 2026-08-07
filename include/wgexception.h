/*
 * libwgcpp — C++ wrapper for embeddable-wg-library
 * Copyright (C) 2026  Ledovskiy Maksim aka fluffymax2005 <santech_montage@mail.ru>
 *
 * This file is part of libwgcpp.
 *
 * libwgcpp is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * libwgcpp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with libwgcpp. If not, see <https://www.gnu.org/licenses/>.
*/

/**
 * @file Contains custom exception to alert about runtime errors related to library
 * @brief
*/


#ifndef WGEXCEPTION_H
#define WGEXCEPTION_H

#include <stdexcept>

/**
 * @brief Custom exception to alert about runtime errors related to library.
 */
class WgException : public std::runtime_error {
public:

    /**
     * @brief Constructor. Make object with given error code.
     * @param message string representation of error. Message should <b>not</b> end with '.'
     * @param error_code error code
     * @throw exceptions inherited by std::runtime_error
     */
    WgException(const std::string& message, int error_code);

    /**
     * @brief Gives string representation of error.
     * @return error string alike <TT>message + ". Error code = " + code</TT>.
     */
    virtual const char* what() const noexcept override;

    /**
     * @brief Get error code
     * @return WgException::code
     */
    int getCode() const noexcept;
protected:
    /**
     * @brief Error code
     */
    int code;
};

#endif // WGEXCEPTION_H
