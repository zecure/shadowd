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

#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "singleton.h"
#include "shared.h"

namespace swd {
    /**
     * @brief Encapsulates and handles the configuration parsing.
     */
    class config :
     public swd::singleton<swd::config> {
        public:
            /**
             * @brief Construct the config and add all possible options.
             */
            config();

            /**
             * @brief Parse the command line and apply it to the config.
             *
             * @param argc The number of command line arguments
             * @param argv The command line arguments
             */
            void parse_command_line(int argc, char** argv);

            /**
             * @brief Parse a file and apply it to the config.
             *
             * @param file The file that gets parsed
             */
            void parse_config_file(const std::string& file);

            /**
             * @brief Validate the configuration and throw an exception if something
             *  important is not set.
             */
            void validate() const;

            /**
             * @brief Test if the configuration value is set.
             *
             * defined and get are just simple wrappers for boost::program_options
             * functionality at the moment. This way the po lib stays isolated and
             * it is easier to replace it later if there is a reason to do so.
             *
             * @param key The key of the configuration value
             */
            bool defined(const std::string& key) const { return (vm_.count(key) > 0); }

            /**
             * @brief Get the configuration value.
             *
             * @see defined
             *
             * @param key The key of the configuration value
             */
            template<class T> T get(const std::string& key) const { return vm_[key].as<T>(); }

        private:
            /**
             * @brief Contains all information about generic settings.
             */
            po::options_description od_generic_;

            /**
             * @brief Contains all information about server settings.
             */
            po::options_description od_server_;

            /**
             * @brief Contains all information about daemon settings.
             */
            po::options_description od_daemon_;

            /**
             * @brief Contains all information about security settings.
             */
            po::options_description od_security_;

            /**
             * @brief Contains all information about database settings.
             */
            po::options_description od_database_;

            /**
             * @brief Contains the actual values of all settings.
             */
            po::variables_map vm_;
    };
}

#endif /* CONFIG_H */
