/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2022 Hendrik Buchwald <hb@zecure.org>
 *
 * This file is part of Shadow Daemon. Shadow Daemon is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#ifndef CACHED_H
#define CACHED_H

#include <ctime>

namespace swd {
    /**
     * @brief Encapsulates cache objects to keep track of their activity.
     */
    template <class T> class cached {
        public:
            /**
             * @brief Construct a cached object.
             *
             * @param value The element that is encapsulated
             */
            cached(const T& value) :
             value_(value),
             counter_(0),
             last_(time(nullptr)) {
            }

            /**
             * @brief Update stats and return the element that is encapsulated.
             *
             * @return The element that is encapsulated
             */
            const T& get_value() {
                /* Increase counter, but do not allow overflowing. */
                if (counter_++ > 4096) {
                    counter_ = 1024;
                }

                /* Update the last access time. */
                last_ = time(nullptr);

                return value_;
            }

            /**
             * @brief Check if the last access time was too long ago.
             *
             * @return Status of the outdated check.
             */
            bool is_outdated() const {
                if (counter_ < 5) {
                    return ((time(nullptr) - last_) > 300);
                } else if (counter_ < 25) {
                    return ((time(nullptr) - last_) > 600);
                } else {
                    return ((time(nullptr) - last_) > 900);
                }
            }

        private:
            /**
             * @brief The element that is encapsulated.
             */
            T value_;

            /**
             * @brief The access counter for the element.
             */
            int counter_;

            /**
             * @brief The last access time for the element.
             */
            time_t last_;
    };
}

#endif /* CACHED_H */
