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

#include "analyzer.h"
#include "blacklist.h"
#include "whitelist.h"
#include "blacklist_rule.h"
#include "database.h"

swd::analyzer::analyzer(swd::request_ptr request) :
 request_(request) {
}

void swd::analyzer::start() {
	if (request_->get_profile()->is_blacklist_enabled()) {
		/**
		 * First we initialize the blacklist. This way the rules are only read once per
		 * request and we have a neat cache for the regex objects.
		 */
		swd::blacklist blacklist(request_);

		/**
		 * The blacklist checks the PHPIDS rules against all parameters and generates an
		 * impact based on the result for every single parameter. The impacts are saved
		 * directly in the request object.
		 */
		blacklist.scan();
	}

	if (request_->get_profile()->is_whitelist_enabled()) {
		swd::whitelist whitelist(request_);

		/**
		 * The whitelist checks for all parameters if there exists a rule and if it
		 * is adhered to. Every parameter that does not gets tagged in the request
		 * object. At the moment three things get checked: the existence of a rule,
		 * the length of the input and the character set.
		 */
		whitelist.scan();
	}

	/* Combine the results and determine which parameters are threats. */
	swd::parameters& parameters = request_->get_parameters();

	for (swd::parameters::iterator it_parameter = parameters.begin();
	 it_parameter != parameters.end(); it_parameter++) {
		/* Save the iterators in variables for the sake of readability. */
		swd::parameter_ptr parameter((*it_parameter).second);

		if (request_->get_profile()->is_blacklist_enabled()) {
			int threshold = request_->get_profile()->get_threshold();

			swd::blacklist_rules rules = swd::database::i()->get_blacklist_rules(
				request_->get_profile()->get_id(),
				request_->get_caller(),
				(*it_parameter).first
			);

			if (rules.size() > 0) {
				/* Get the most secure threshold in case of an overlap. */
				for (swd::blacklist_rules::iterator it_rule = rules.begin();
				 it_rule != rules.end(); it_rule++) {
					swd::blacklist_rule_ptr rule(*it_rule);

					if (it_rule == rules.begin()) {
						threshold = rule->get_threshold();
					} else if (rule->get_threshold() > -1) {
						if ((threshold < 0) || (rule->get_threshold() < threshold)) {
							threshold = rule->get_threshold();
						}
					}
				}
			}

			/* Check if the impact is higher than the threshold. */
			if ((threshold > -1) && (parameter->get_impact() > threshold)) {
				parameter->is_threat(true);
				parameter->has_critical_impact(true);
			}
		}

		if (request_->get_profile()->is_whitelist_enabled()) {
			/* Check if there is no responsible whitelist rule. */
			if (parameter->get_total_rules() == 0) {
				parameter->is_threat(true);
			}

			/* Check if there are whitelist rules that are not adhered to. */
			if (parameter->get_whitelist_rules().size() > 0) {
				parameter->is_threat(true);
			}
		}
	}
}
