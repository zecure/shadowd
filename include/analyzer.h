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

#ifndef ANALYZER_H
#define ANALYZER_H

#include "request.h"

namespace swd {
	/**
	 * @brief Manages the examination of a request.
	 *
	 * At the moment the white- and blacklist get checked and results are
	 * written directly into the request. Maybe there will be additional checks
	 * in later versions.
	 */
	class analyzer {
		public:
			/**
			 * @brief Construct the analyzer.
			 *
			 * @param request The pointer to the request object
			 */
			analyzer(swd::request_ptr request);

			/**
			 * @brief Start the analysis and write results into the request object.
			 */
			void start();

		private:
			swd::request_ptr request_;
	};
}

#endif /* ANALYZER_H */
