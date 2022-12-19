/**
 \file 		parse_options.h
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 ENCRYPTO Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Parse Options Implementation
 */

#ifndef UTIL_PARSE_OPTIONS_H_
#define UTIL_PARSE_OPTIONS_H_

#include <cstdint>
#include <string>
#include <vector>

/**
 \enum 	etype
 \brief	Data types for command line parameters
 */
enum etype {
	T_NUM, //uint32_t number
	T_STR, //string
	T_FLAG, //boolean flag
	T_DOUBLE //double number
};


/**
 \struct 	parsing_ctx
 \brief	holds information about parameters that should be parsed in the command line input
 */
struct parsing_ctx {
	void* val;	//value of the option, is written into by parse_options
	etype type;	//type of value
	std::string opt_name; //name 