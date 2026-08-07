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
 * @file
 * @brief Two modes for library to behave: thread safe or unsafe
 */

#ifndef THREADSAFETY_H
#define THREADSAFETY_H

#include <mutex>

/**
 * @brief Struct for single threaded app. Provides phony methods and types for working.
 */
struct SingleThreaded {
    /**
     * @brief Phony mutex struct. Methods does nothing.
     */
    struct Mutex {
        /**
         * @brief Does not lock anything.
         */
        inline void lock() {}

        /**
         * @brief Does not unlock anything.
         */
        inline void unlock() {}
    };

    /**
     * @brief Empty struct which should do nothing.
     */
    using Lock = Mutex;
};

/**
 * @brief Struct for multi threaded app. Provides STL methods and types for working.
 */
struct MultiThreaded {
    /**
     * @brief Standart std::mutex mutex.
     */
    using Mutex = std::mutex;

    /**
     * @brief Standart RAII based guard for mutex.
     */
    using Lock = std::lock_guard<std::mutex>;
};

#endif // THREADSAFETY_H