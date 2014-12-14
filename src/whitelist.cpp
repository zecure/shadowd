/**
 * Shadow Daemon -- Web Application Firewall
 *
 *   Copyright (C) 2014 Hendrik Buchwald <hb@zecure.org>
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
 */

#include <boost/lexical_cast.hpp>

#include "whitelist.h"
#include "database.h"
#include "log.h"

swd::whitelist::whitelist(swd::request_ptr request)
 : request_(request) {
	/* Import the rules from the database. */
	rules_ = swd::database::i()->get_whitelist_rules(
		request_->get_profile()->get_id(),
		request_->get_caller()
	);
}

void swd::whitelist::scan() {
	swd::parameters& parameters = request_->get_parameters();

	/* Iterate over all parameters. */
	for (swd::parameters::iterator it_parameter = parameters.begin();
	 it_parameter != parameters.end(); it_parameter++) {
		/* Save the iterators in variables for the sake of readability. */
		swd::parameter_ptr parameter((*it_parameter).second);

		/* Iterate over all rules. */
		for (swd::whitelist_rules::iterator it_rule = rules_.begin();
		 it_rule != rules_.end(); it_rule++) {
			swd::whitelist_rule_ptr rule(*it_rule);

			if (rule->is_responsible((*it_parameter).first)) {
				/**
				 * The parameter needs at least one rule to pass the check. Otherwise
				 * it wouldn't be a whitelist.
				 */
				parameter->increment_rules_counter();

				try {
					/* Add pointers to all rules that are not adhered to by this parameter. */
					if (!rule->is_adhered_to(parameter->get_value())) {
						parameter->add_whitelist_rule(rule);
					}
				} catch (...) {
					swd::log::i()->send(swd::uncritical_error, "Unexpected whitelist problem");
				}
			}
		}
	}
}
