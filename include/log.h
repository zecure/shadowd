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

#ifndef LOG_H
#define LOG_H

#include <string>
#include <boost/thread/mutex.hpp>

#include "singleton.h"
#include "shared.h"

namespace swd {
    /**
     * @brief Criticality of log message.
     */
    enum log_level {
        critical_error,
        uncritical_error,
        warning,
        notice
    };

    /**
     * @brief Handles the logging.
     */
    class log :
     public swd::singleton<log> {
        public:
            /**
             * @brief Set a file where the logs get written too.
             *
             * @param file The file that the logs get written to
             */
            void open_file(const std::string& file);

            /**
             * @brief Log a message.
             *
             * @param level The severity of the log
             * @param message The message of the log
             */
            void send(const swd::log_level& level, const std::string& message);

        private:
            /**
             * @brief Get the current date and time as string.
             *
             * @return The current date and time in a readable format
             */
            std::string get_current_time() const;

            /**
             * @brief The log file. If empty stderr is used instead.
             */
            std::string file_;

            /**
             * @brief The mutex for the output.
             */
            boost::mutex mutex_;
    };
}

#endif /* LOG_H */
