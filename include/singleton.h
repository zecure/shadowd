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

#ifndef SINGLETON_H
#define SINGLETON_H

namespace swd {
	/**
	 * @brief Interface for singleton classes.
	 */
	template <typename C> class singleton {
		public:
			virtual ~singleton () {
				instance_ = 0;
			}
			/**
			 * @brief Get the global instance of the template class.
			 *
			 * @return Pointer to the template class.
			 */
			static C* i() {
				if (!instance_) {
					instance_ = new C();
				}

				return instance_;
			}

		private:
			static C* instance_;

		protected:
			singleton() {}
	};

	template <typename C> C* singleton <C>::instance_ = 0;
}

#endif /* SINGLETON_H */
