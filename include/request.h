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

#ifndef REQUEST_H
#define REQUEST_H

#include <string>
#include <boost/shared_ptr.hpp>

#include "profile.h"
#include "parameter.h"
#include "hash.h"
#include "integrity_rule.h"

namespace swd {
    /**
     * @brief Models a request.
     *
     * In contrast to most other model classes in this project the request does
     * not have all of his information at the time of construction. Instead first
     * the signature and raw content get appended character by character. After
     * that is done the signature gets checked and the raw content gets decoded.
     * If there was no error this is the point where the request object contains
     * all of its information in a clear format.
     */
    class request {
        public:
            /**
             * @brief Set the pointer of the profile.
             *
             * @param profile The profile of the connection
             */
            void set_profile(const swd::profile_ptr& profile);

            /**
             * @brief Get the pointer of the profile.
             *
             * @return The profile that got assigned to this request
             */
            swd::profile_ptr get_profile() const;

            /**
             * @brief Add a parameter object to the request.
             *
             * @param parameter The parameter
             */
            void add_parameter(const swd::parameter_ptr& parameter);

            /**
             * @brief Create and add a parameter object to the request.
             *
             * @param path The path of the parameter
             * @param value The value of the parameter
             */
            void add_parameter(const std::string& path, const std::string& value);

            /**
             * @brief Get all saved parameters.
             *
             * @return The reference of the parameter list
             */
            const swd::parameters& get_parameters() const;

            /**
             * @brief Append a character to the content string.
             *
             * This function is used by the request_parser to construct the raw
             * content character by character.
             *
             * @param input The character that gets appended
             */
            void append_content(const char& input);

            /**
             * @brief Get the complete json content.
             *
             * @param content The complete encoded content
             */
            void set_content(const std::string& content);

            /**
             * @brief Set the complete json content.
             *
             * @return The complete encoded content.
             */
            std::string get_content() const;

            /**
             * @brief Append a character to the signature string.
             *
             * This function is used by the request_parser to construct the raw
             * signature character by character.
             *
             * @param input The character that gets appended
             */
            void append_signature(const char& input);

            /**
             * @brief Set the complete signature.
             *
             * @param signature The complete signature
             */
            void set_signature(const std::string& signature);

            /**
             * @brief Get the complete signature.
             *
             * @return The complete signature.
             */
            std::string get_signature() const;

            /**
             * @brief Append a character to the profile id.
             *
             * This function is used by the request_parser to construct the raw
             * profile id character by character.
             *
             * @param input The character digit that gets appended
             */
            void append_profile_id(const char& input);

            /**
             * @brief Set the complete profile id.
             *
             * @param profile_id The complete profile id
             */
            void set_profile_id(const unsigned long long& profile_id);

            /**
             * @brief Get the complete profile id.
             *
             * @return The complete profile id.
             */
            unsigned long long get_profile_id() const;

            /**
             * @brief Set the http client/attacker ip.
             *
             * @param client_ip The ip of the attacker
             */
            void set_client_ip(const std::string& client_ip);

            /**
             * @brief Get the http client/attacker ip.
             *
             * @return The ip of the attacker
             */
            std::string get_client_ip() const;

            /**
             * @brief Set the caller of this request.
             *
             * @param caller The caller
             */
            void set_caller(const std::string& caller);

            /**
             * @brief Get the caller of this request.
             *
             * @return The caller
             */
            std::string get_caller() const;

            /**
             * @brief Set the resource of this request.
             *
             * @param resource The resource
             */
            void set_resource(const std::string& resource);

            /**
             * @brief Get the resource of this request.
             *
             * @return The resource
             */
            std::string get_resource() const;

            /**
             * @brief Add a (broken) integrity rule to this request.
             *
             * @param rule The pointer to the integrity rule object
             */
            void add_integrity_rule(const swd::integrity_rule_ptr& rule);

            /**
             * @brief Get all (broken) integrity rules.
             *
             * @return The list of saved integrity rules
             */
            const swd::integrity_rules& get_integrity_rules() const;

            /**
             * @brief Set the number of integrity rules.
             *
             * Parameters with not integrity rule are also classified as an
             * attack, so we have to keep track of the responsible rules.
             */
            void set_total_integrity_rules(const int& total_integrity_rules);

            /**
             * @brief Get the total number of responsible integrity rules.
             *
             * @return The total number of checked integrity rules
             */
            int get_total_integrity_rules() const;

            /**
             * @brief Add a hash to the request.
             *
             * @param algorithm The algorithm that is used to calculate the hash
             * @param digest The output of the hash algorithm on the message
             */
            void add_hash(const std::string& algorithm, const std::string& digest);

            /**
             * @brief Get all saved hashes.
             *
             * @return The hashes of the request
             */
            const swd::hashes& get_hashes() const;

            /**
             * @brief Get the hash of a specific algorithm.
             *
             * @param algorithm The algorithm that is used to calculate the hash
             * @return The hash of the algorithm
             */
            swd::hash_ptr get_hash(const std::string& algorithm) /*const*/;

            /**
             * @brief Define if this request itself is a threat or not.
             *
             * @param threat Threat status of this request
             */
            void set_threat(const bool& threat);

            /**
             * @brief Check if the request itself is a threat.
             *
             * If the request itself is a threat it has to be completely blocked.
             *
             * @return If the request is classified as threat
             */
            bool is_threat() const;

            /**
             * @brief Check if this request has parameters with threats.
             *
             * If only a sub part of the request is a threat it can be filtered out.
             *
             * @return If the request has threats
             */
            bool has_threats() const;

        private:
            /**
             * @brief The pointer to the profile object.
             */
            swd::profile_ptr profile_;

            /**
             * @brief A vector of parameters.
             */
            swd::parameters parameters_;

            /**
             * @brief A vector of hashes.
             */
            swd::hashes hashes_;

            /**
             * @brief The raw content of the request.
             */
            std::string content_;

            /**
             * @brief The signature of the request.
             */
            std::string signature_;

            /**
             * @brief The profile id of the request as string.
             */
            std::string profile_id_;

            /**
             * @brief The client ip.
             */
            std::string client_ip_;

            /**
             * @brief The caller of the request.
             */
            std::string caller_;

            /**
             * @brief The requested resource of the request.
             */
            std::string resource_;

            /**
             * @brief The threat status of the request.
             */
            bool threat_ = false;

            /**
             * @brief A vector of broken integrity rules.
             */
            swd::integrity_rules integrity_rules_;

            /**
             * @brief The total number of matching integrity rules.
             */
            int total_integrity_rules_ = 0;
    };

    /**
     * @brief Request pointer.
     */
    using request_ptr = boost::shared_ptr<swd::request>;
}

#endif /* REQUEST_H */
