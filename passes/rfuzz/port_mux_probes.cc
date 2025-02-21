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
 *  This pass concatenates the multiplexer select signals to a SigSpec to form a coverage port. This
 *  is required by the harness generator.
 */

#include "kernel/yosys.h"
#include "kernel/log.h"
#include "kernel/rtlil.h"

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

std::string sanitize_wire_name(std::string wire_name) {
		std::string ret;
		ret.reserve(wire_name.size());
		for(size_t char_id = 0; char_id < wire_name.size(); char_id++) {
			char curr_char = wire_name[char_id];
			if(curr_char != '$' && curr_char != ':' && curr_char != '.' && curr_char != '\\' && curr_char != '[' && curr_char != ']')
				ret += wire_name[char_id];
		}
		return '\\'+ret;
	}

static std::map<std::string, int> count_wires(RTLIL::Module *module){
	std::map<std::string, int> n_wires_map;
	for(auto m: module->design->modules()){
		for (auto &wire_iter : module->wires_){
			if(wire_iter.second->has_attribute(ID(mux_wire)) && wire_iter.second->has_attribute(m->name.c_str())){
				n_wires_map[string(m->name.c_str())]++;
			}
		}

	}
	return n_wires_map;
}

static void gen_mux_port( RTLIL::Design *design, bool opt_verbose){
	RTLIL::Module *module = design->top_module();
	std::map<std::string, int> n_wires_map = count_wires(module);
	int n_wires = 0;
	for(auto &n_wires_module: n_wires_map){
		log("Module %s has %i probes\n", n_wires_module.first.c_str(),n_wires_module.second);
		n_wires += n_wires_module.second;
	}

	log("Creating port for %i mux wires.\n", n_wires);
	RTLIL::SigSpec mux_wires = SigSpec();
    for (auto &wire_iter : module->wires_){
		RTLIL::Wire *wire = wire_iter.second;

		if (!design->selected(module, wire))
			continue;

        if(wire->has_attribute(ID(mux_wire))){
            if(opt_verbose) log("Adding mux signal %s to port\n", RTLIL::id2cstr(wire->name));
			mux_wires.append(wire);
			wire->port_output = false;
        }
    }
	RTLIL::Wire *mux_port = module->addWire("\\auto_cover_out", n_wires);
	mux_port->set_bool_attribute(ID(mux_wire));
	module->connect(mux_port,mux_wires);
	mux_port->port_output = true;
	mux_port->set_bool_attribute(ID(port));
	module->fixup_ports();

}
struct PortMuxProbesPass : public Pass {
	PortMuxProbesPass() : Pass("port_mux_probes") { }

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    port_mux_probes\n");
		log("\n");
		log("Creates port for mux probes.\n");
		log("\n");
		log("Options:\n");
		log("\n");
		log("  -verbose\n");
		log("    Verbose mode.\n");
	}
	
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{

		bool opt_verbose = false;

		std::vector<std::string>::size_type argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "-verbose") {
				opt_verbose = true;
				continue;
			}
		}

		log_header(design, "Executing port_mux_probes pass (Concat mux probe signals to form port).\n");
		gen_mux_port(design, opt_verbose);           
				
	}
} PortMuxProbesPass;

PRIVATE_NAMESPACE_END
