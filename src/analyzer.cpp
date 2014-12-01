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

#include "analyzer.h"
#include "blacklist.h"
#include "whitelist.h"

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
		blacklist.init();

		/**
		 * The blacklist checks the PHPIDS rules against all parameters and generates an
		 * impact based on the result for every single parameter. The impacts are saved
		 * directly in the request object.
		 */
		blacklist.scan();
	}

	/* If the (whitelist) learning mode is activated the whitelist check is disabled. */
	if (request_->get_profile()->is_whitelist_enabled() && !request_->get_profile()->is_learning_enabled()) {
		/* The learning mode is not activated, so continue to create a whitelist object. */
		swd::whitelist whitelist(request_);
		whitelist.init();

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
			/* Check if the impact is higher than the threshold. */
			if (parameter->get_impact() > request_->get_profile()->get_threshold()) {
				parameter->is_threat(true);
				parameter->has_critical_impact(true);
			}
		}

		if (request_->get_profile()->is_whitelist_enabled() && !request_->get_profile()->is_learning_enabled()) {
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
