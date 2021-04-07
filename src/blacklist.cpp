/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014-2021 Hendrik Buchwald <hb@zecure.org>
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

#include "blacklist.h"

#include <utility>
#include "blacklist_rule.h"
#include "log.h"

swd::blacklist::blacklist(swd::cache_ptr cache) :
 cache_(std::move(cache)) {
}

void swd::blacklist::scan(swd::request_ptr& request) {
    swd::blacklist_filters filters = cache_->get_blacklist_filters();
    swd::parameters parameters = request->get_parameters();

    /* Iterate over all parameters and check every filter. */
    for (const auto& parameter: parameters) {
        for (const auto& filter: filters) {
            /* If there is catastrophic backtracking boost throws an exception. */
            try {
                /* Add pointers to all filters that match to the parameter. */
                if (filter->matches(parameter->get_value())) {
                    parameter->add_blacklist_filter(filter);
                }
            } catch (...) {
                swd::log::i()->send(swd::uncritical_error, "Unexpected blacklist problem");

                /* Add the filter anyway to avoid a potential bypass. */
                parameter->add_blacklist_filter(filter);
            }
        }
    }

    /* Iterate over all parameters again and check total impact. */
    for (const auto& parameter: parameters) {
        swd::blacklist_rules rules = cache_->get_blacklist_rules(
            request->get_profile()->get_id(),
            request->get_caller(),
            parameter->get_path()
        );

        int threshold = request->get_profile()->get_blacklist_threshold();

        /* Blacklist rules take priority over the profile threshold. */
        if (!rules.empty()) {
            threshold = -1;
            for (const auto& rule: rules) {
                /* Get the most secure (i.e. lowest) threshold in case of an overlap. */
                if ((rule->get_threshold() > -1) && (rule->get_threshold() < threshold)) {
                    threshold = rule->get_threshold();
                }
            }
        }

        /* Check if the impact is higher than the threshold. */
        if ((threshold > -1) && (parameter->get_impact() > threshold)) {
            parameter->set_threat(true);
            parameter->set_critical_blacklist_impact(true);
        }
    }
}
