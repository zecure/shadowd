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

#ifndef LOG_H
#define LOG_H

#include <string>

#include "singleton.h"
#include "shared.h"

namespace swd {
	/**
	 * @brief Criticality of log message.
	 */
	enum log_level {
		critical_error,
		uncritical_error,
		warning,
		notice
	};

	/**
	 * @brief Handles the logging.
	 */
	class log :
	 public swd::singleton<log> {
		public:
			/**
			 * @brief Set a file where the logs get written too.
			 *
			 * @param file The file that the logs get written to
			 */
			void open_file(std::string file);

			/**
			 * @brief Log a message.
			 *
			 * @param level The severity of the log
			 * @param message The message of the log
			 */
			void send(swd::log_level level, std::string message);

		private:
			std::string get_current_time();
			std::string file_;
	};
}

#endif /* LOG_H */
