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

#ifndef BLACKLIST_H
#define BLACKLIST_H

#include "request.h"
#include "cache.h"

namespace swd {
    /**
     * @brief Handles the blacklist examination of a request.
     */
    class blacklist {
        public:
            /**
             * @brief Construct the blacklist.
             *
             * @param cache The pointer to the cache object
             */
            blacklist(swd::cache_ptr cache);

            /**
             * @brief Scan all parameters in the request and add connections to
             *  matching filters.
             *
             * @param request The pointer to the request object
             */
            void scan(const swd::request_ptr& request) const;

        private:
            /**
             * @brief If available get threshold from blacklist rule, otherwise from profile.
             *
             * @param request The pointer to the request object
             * @param parameter The pointer to the parameter object
             * @return The threshold value for the parameter
             */
            int get_threshold(const swd::request_ptr& request, const swd::parameter_ptr& parameter) const;

            /**
             * @brief The pointer to the cache object.
             */
            swd::cache_ptr cache_;
    };
}

#endif /* BLACKLIST_H */
