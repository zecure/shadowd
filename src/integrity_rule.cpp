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

#include "integrity_rule.h"

void swd::integrity_rule::set_id(const unsigned long long& id) {
    id_ = id;
}

unsigned long long swd::integrity_rule::get_id() const {
    return id_;
}

void swd::integrity_rule::set_algorithm(const std::string& algorithm) {
    algorithm_ = algorithm;
}

std::string swd::integrity_rule::get_algorithm() const {
    return algorithm_;
}

void swd::integrity_rule::set_digest(const std::string& digest) {
    digest_ = digest;
}

std::string swd::integrity_rule::get_digest() const {
    return digest_;
}

bool swd::integrity_rule::matches(const swd::hash_ptr& hash) const {
    /* Stop if there is no hash (for this algorithm). */
    if (!hash) {
        return false;
    }

    /* The algorithms should always match, but better safe than sorry. */
    if (algorithm_ != hash->get_algorithm()) {
        return false;
    }

    /* No need to compare the digests if the length is different. */
    std::string user_digest = hash->get_digest();

    if (digest_.length() != user_digest.length()) {
        return false;
    }

    /* Use constant-time comparison for the digests to avoid timing attacks. */
    std::byte result{};

    for (unsigned int i = 0; i < digest_.length(); i++) {
        result |= std::byte(digest_.at(i)) ^ std::byte(user_digest.at(i));
    }

    return (std::to_integer<int>(result) == 0);
}
