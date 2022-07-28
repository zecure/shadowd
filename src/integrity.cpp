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

#include <utility>

#include "integrity.h"
#include "integrity_rule.h"
#include "hash.h"
#include "log.h"

swd::integrity::integrity(swd::cache_ptr cache) :
 cache_(std::move(cache)) {
}

void swd::integrity::scan(const swd::request_ptr& request) const {
    /* Import the rules from the database. */
    swd::integrity_rules rules = cache_->get_integrity_rules(
        request->get_profile()->get_id(),
        request->get_caller()
    );

    /**
     * The request needs at least one rule to pass the check. Otherwise
     * it wouldn't be a whitelist.
     */
    request->set_total_integrity_rules((int)rules.size());

    if (request->get_total_integrity_rules() == 0) {
        request->set_threat(true);
    }

    /* Iterate over all rules. */
    for (const auto& rule: rules) {
        try {
            swd::hash_ptr hash = request->get_hash(rule->get_algorithm());

            /* Add pointers to all rules that do not match. */
            if (!rule->matches(hash)) {
                request->add_integrity_rule(rule);
                request->set_threat(true);
            }
        } catch (...) {
            swd::log::i()->send(swd::uncritical_error, "Unexpected integrity problem");

            /* Add the rule anyway to avoid a potential bypass. */
            request->add_integrity_rule(rule);
            request->set_threat(true);
        }
    }
}
