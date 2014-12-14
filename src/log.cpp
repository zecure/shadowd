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

#include <fstream>
#include <ostream>
#include <iostream>

#include "log.h"
#include "config.h"

void swd::log::open_file(std::string file) {
	file_ = file;
}

void swd::log::send(swd::log_level level, std::string message) {
	/* Skip warning & notice if verbose is not enabled. */
	if (!swd::config::i()->defined("verbose")) {
		if ((level == warning) || (level == notice)) {
			return;
		}
	}

	/* Build an informative output line. */
	std::stringstream line;

	line << get_current_time() << "\t";

	switch (level) {
		case critical_error:
			line << "Critical error";
			break;
		case uncritical_error:
			line << "Uncritical error";
			break;
		case warning:
			line << "Warning";
			break;
		case notice:
			line << "Notice";
			break;
	}

	line << "\t" << message << "\n";

	/* Write the final line into a log file or stderr. */
	if (!file_.empty()) {
		std::ofstream out_file(file_.c_str(), std::ios_base::app);

		if (!out_file.is_open()) {
			return;
		}

		out_file << line.str();
		out_file.close();
	} else {
		std::cerr << line.str();
	}
}

std::string swd::log::get_current_time() {
	time_t now = time(0);
	char buf[80];
	struct tm tstruct = *localtime(&now);

	strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
	return buf;
}
