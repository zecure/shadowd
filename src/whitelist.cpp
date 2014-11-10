/**
 * Shadow Daemon -- High-Interaction Web Honeypot
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

#include "whitelist.h"
#include "database.h"
#include "log.h"

swd::whitelist::whitelist(swd::request_ptr request)
 : request_(request) {
}

void swd::whitelist::init() {
	/* Import the rules from the database. */
	swd::database_rows rules = swd::database::i()->get_whitelist_rules(
		request_->get_profile()->get_id(),
		request_->get_caller()
	);

	for (swd::database_rows::iterator it_rule = rules.begin();
	 it_rule != rules.end(); ++it_rule) {
		swd::whitelist_filter_ptr filter(
			new swd::whitelist_filter(
				atoi((*it_rule)["filter_id"].c_str()),
				(*it_rule)["rule"]
			)
		);

		swd::whitelist_rule_ptr rule(
			new swd::whitelist_rule(
				atoi((*it_rule)["id"].c_str()),
				(*it_rule)["path"],
				filter,
				atoi((*it_rule)["min_length"].c_str()),
				atoi((*it_rule)["max_length"].c_str())
			)
		);

		/* Save the smart pointer of the rule in a vector. */
		rules_.push_back(rule);
	}
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

				/* Add pointers to all rules that are not adhered to by this parameter. */
				if (!rule->is_adhered_to(parameter->get_value())) {
					parameter->add_whitelist_rule(rule);
				}
			}
		}
	}
}
