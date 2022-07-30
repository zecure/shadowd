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

#ifndef HASH_H
#define HASH_H

#include <map>
#include <string>
#include <boost/shared_ptr.hpp>

namespace swd {
    /**
     * @brief Models a hash.
     */
    class hash {
        public:
            /**
             * @brief Set the algorithm of the hash.
             *
             * @param algorithm The algorithm of the hash
             */
            void set_algorithm(const std::string& algorithm);

            /**
             * @brief Get the algorithm of the hash.
             *
             * @return The algorithm of the hash
             */
            std::string get_algorithm() const;

            /**
             * @brief Set the digest of the hash.
             *
             * @param digest The digest of the hash
             */
            void set_digest(const std::string& digest);

            /**
             * @brief Get the digest of the hash.
             *
             * @return The digest of the hash
             */
            std::string get_digest() const;

        private:
            /**
             * @brief The algorithm of the hash.
             */
            std::string algorithm_;

            /**
             * @brief The digest of the hash.
             */
            std::string digest_;
    };

    /**
     * @brief Hash pointer.
     */
    using hash_ptr = boost::shared_ptr<swd::hash>;

    /**
     * @brief Map of hashes pointers. The key is the algorithm.
     */
    using hashes = std::map<std::string, swd::hash_ptr>;
}

#endif /* HASH_H */
