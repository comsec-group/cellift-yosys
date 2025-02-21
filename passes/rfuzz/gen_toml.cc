/*
 *  yosys -- Yosys Open SYnthesis Suite
 *
 *  Copyright (C) 2022  Tobias Kovats <tkovats@student.ethz.ch> & Flavien Solt <flsolt@ethz.ch>
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  This pass outputs the meta information about the instrumentation and DUT as requried by the harness generator.
 */

#include "kernel/yosys.h"
#include "kernel/log.h"
#include "kernel/rtlil.h"
#include <iostream>
#include <fstream>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN


static bool cmp(pair<RTLIL::IdString, RTLIL::Wire*> a, pair<RTLIL::IdString,RTLIL::Wire*> b){
    return (a.second->width > b.second->width);
}

static void gen_toml(RTLIL::Design *design, std::string filename, std::vector<std::string> excluded_signals){
	RTLIL::Module *module = design->top_module();
    std::ofstream toml_file;
    toml_file.open(filename.c_str());
    toml_file << "[general]\n";
    toml_file << "filename = \"???\"\n";
    toml_file << "instrumented = \"" << RTLIL::id2cstr(module->name) << ".v\"\n";
    toml_file << "top = \"" << RTLIL::id2cstr(module->name) << "\"\n";
    toml_file << "timestamp = 2023-04-05T12:59:15Z\n"; // TODO use real timestamp here
    toml_file << "\n";
    int cov_idx = 0;
    int assert_idx = 0;
    int cellift_in_idx = 0;
    int cellift_out_idx = 0;
    vector<pair<RTLIL::IdString, RTLIL::Wire*>> wire_vec;

    for(auto &wire_iter: module->wires_) {
        wire_vec.push_back(pair<RTLIL::IdString, RTLIL::Wire*>(wire_iter.first, wire_iter.second));
    }

    sort(wire_vec.begin(), wire_vec.end(), cmp); // need to order by bit width for fuzzing engine

    for (auto &wire_iter: wire_vec){

		RTLIL::Wire *wire = wire_iter.second;
        for(auto &exclude: excluded_signals){
            if(!strcmp(RTLIL::id2cstr(wire->name),exclude.c_str())) goto SKIP;
        }

		if (!design->selected(module, wire))
			continue;

        if(wire->has_attribute(ID(port))){ 
            toml_file << "[[coverage_port]]\n";
            toml_file << "name = \"" << RTLIL::id2cstr(wire->name) << "\"\n";
            toml_file << "width = "  << wire->width << "\n";
            toml_file << "\n";
        }

        else if(wire->has_attribute(ID(cellift_port))){ 
            toml_file << "[[cellift_port]]\n";
            toml_file << "name = \"" << RTLIL::id2cstr(wire->name) << "\"\n";
            toml_file << "width = "  << wire->width << "\n";
            toml_file << "\n";
        }

        else if(!wire->width) continue; // empty wires are only included for ports as requried by harness
        // if cellift input
        else if(wire->has_attribute(ID(cellift_in))){ // TODO the order of wires might be messed up!
            toml_file << "[[cellift]]\n";
            toml_file<< "port = \"cellift_in\"\n";
            toml_file << "name = \"" << RTLIL::id2cstr(wire->name) << "\"\n";
            toml_file << "width = " << wire->width << "\n";
            toml_file << "index = " << cellift_in_idx << "\n";
            toml_file << "\n";
            cellift_in_idx += wire->width;
        }
        // if cellift output
        else if(wire->has_attribute(ID(cellift_out))){
            toml_file << "[[cellift]]\n";
            toml_file<< "port = \"cellift_out\"\n";
            toml_file << "name = \"" << RTLIL::id2cstr(wire->name) << "\"\n";
            toml_file << "width = " << wire->width << "\n";
            toml_file << "index = " << cellift_out_idx << "\n";
            toml_file << "\n";
            cellift_out_idx += wire->width;
        }
        // if output is mux probe, exclude taints
        else if(wire->has_attribute(ID(mux_wire)) && !wire->has_attribute(ID(cellift))){
            toml_file << "[[coverage]]\n";
            toml_file<< "port = \"auto_cover_out\"\n";
            toml_file << "name = \"" << RTLIL::id2cstr(wire->name) << "\"\n";
            toml_file << "width = " << wire->width << "\n";
            toml_file << "index = " << cov_idx << "\n";
            toml_file << "filename = \"\"\n";
            toml_file << "line = -1\n";
            toml_file << "column = -1\n";
            toml_file << "human = \"\"\n";
            cov_idx += wire->width;
            toml_file << "\n";

        }
        // if output is assert probe, exclude taints
        else if(wire->has_attribute(ID(assert_wire)) && !wire->has_attribute(ID(cellift))){
            toml_file << "[[coverage]]\n";
            toml_file<< "port = \"assert_out\"\n";
            toml_file << "name = \"" << RTLIL::id2cstr(wire->name) << "\"\n";
            toml_file << "width = " << wire->width << "\n";
            toml_file << "index = " << assert_idx << "\n";
            toml_file << "filename = \"\"\n";
            toml_file << "line = -1\n";
            toml_file << "column = -1\n";
            toml_file << "human = \"\"\n";
            assert_idx += wire->width;
            toml_file << "\n";

        }
        // if just regular IO list here
        else if(wire->port_input){
            toml_file << "[[input]]\n";
            toml_file << "name = \"" << RTLIL::id2cstr(wire->name) << "\"\n";
            toml_file << "width = " << wire->width << "\n";
            toml_file << "\n";

        }
        else if(wire->port_output){
            toml_file << "[[output]]\n";
            toml_file << "name = \"" << RTLIL::id2cstr(wire->name) << "\"\n";
            toml_file << "width = " << wire->width << "\n";
            toml_file << "\n";
        }

        SKIP: continue;
       
    }
    toml_file.close();

}
struct GenTomlPass : public Pass {
	GenTomlPass() : Pass("gen_toml") { }

    void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    gen_toml <output_file> <exdluded_signals>\n");
		log("\n");
		log("Generate toml file for harness.\n");
		log("\n");
		log("Options:\n");
	}

	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
        if(args.size()<2) {
            log("No output file specified.\n");
            return;
        }
        log_header(design, "Executing gen_toml pass (generate meta info for harness).\n");

        std::string output_file = args[1];

        std::vector<std::string> excluded_signals;
        if(args.size()>2){
            std::stringstream ss(args[2].c_str());
            log("Excluding signals %s\n", args[2].c_str());
            while(ss.good()){
                    std::string substr;
                    std::getline(ss,substr, ',' );
                    excluded_signals.push_back(substr);
                }

        }
        gen_toml(design, output_file, excluded_signals);
               

	}
} GenTomlPass;

PRIVATE_NAMESPACE_END
