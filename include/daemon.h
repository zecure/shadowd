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

#ifndef DAEMON_H
#define DAEMON_H

#include <string>

namespace swd {
    /**
     * @brief Encapsulates the daemon functionality.
     */
    class daemon {
        public:
            /**
             * @brief Change the uid of the process.
             *
             * @param user The name of the user
             */
            void set_user(const std::string& user) const;

            /**
             * @brief Change the gid of the process.
             *
             * @param group The name of the group
             */
            void set_group(const std::string& group) const;

            /**
             * @brief Write the pid to a file.
             *
             * @param file The file that the pid gets written to
             */
            void write_pid(const std::string& file) const;

            /**
             * @brief Change the root directory of the process.
             *
             * @param directory The directory that is used for chroot
             */
            void change_root(const std::string& directory) const;

            /**
             * @brief Detach the process and make him silent.
             */
            void detach() const;
    };
}

#endif /* DAEMON_H */
