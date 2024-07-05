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
 *  This pass adds a meta reset logic to all registers in the design. The logic is as follows: To each FF a
 *  multiplexer is added. The FF input is then connected to the multiplexer input 0. The multiplexer input 1 is connected
 *  to constant 0. The meta reset wire toggles the multiplexer, setting the FF values to zero when asserted.
 */

#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"
#include "kernel/yosys.h"

#include <algorithm>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

struct MetaResetWorker {
private:
	// Command line arguments.
	bool opt_verbose;
	string opt_signame;
	bool opt_nofixedname;

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

	void create_meta_reset(RTLIL::Module *module, bool is_top) {
		if (opt_verbose)
			log("Adding MetaReset to module %s.\n", module->name.c_str());

		if (module->processes.size())
			log_error("Unexpected process. Requires a `proc` pass before.\n");

        std::string wire_name;
        wire_name = opt_signame;
		if (opt_nofixedname)
        	if(!is_top) wire_name += std::string("_")+RTLIL::id2cstr(module->name);
        wire_name = sanitize_wire_name(wire_name);
        Wire *meta_reset = module->addWire(wire_name, 1);

		for(std::pair<RTLIL::IdString, RTLIL::Cell*> cell_pair : module->cells_) {
			RTLIL::IdString cell_name = cell_pair.first;
			RTLIL::Cell *cell = cell_pair.second;
			int found = 0;
			if(cell->type.in(ID($dff))) { // is cell a flip flop?
				RTLIL::SigSpec port_d(cell->getPort(ID::D));
				RTLIL::SigSpec mux_out = RTLIL::SigSpec();
				for (auto &chunk_it: port_d.chunks()) {
					if(!chunk_it.is_wire()) continue;
					if (opt_verbose)
						log("Adding MetaReset %s to %i-bit register in module %s\n", chunk_it.wire->name.c_str(), chunk_it.width, module->name.c_str());
                    mux_out.append(module->Mux(NEW_ID, chunk_it, Const(State::S0,chunk_it.width), meta_reset)); // add meta reset logic
					found = 1;
				}
				if(found){ // we only add the reset logic if there are indeed wires connected to the FF and not just constants
					cell->unsetPort(ID::D);
					cell->setPort(ID::D, mux_out);
				}
			}

			else if (module->design->module(cell->type) != nullptr) { // cell is a module
				RTLIL::Module *submodule = module->design->module(cell->type);
				for (Wire *submodule_wire: submodule->wires()) {
					if (submodule_wire->has_attribute(ID(meta_reset))) { // output wire is a meta reset
                        if (opt_verbose)
						    log("Connecting submodule wire %s with %s\n", RTLIL::id2cstr(submodule_wire->name), RTLIL::id2cstr(meta_reset->name));
                        cell->setPort(submodule_wire->name.str(), meta_reset); // connect meta reset port of submodule cell to module level meta reset wire
					}
				}
			}
		}
        meta_reset->port_input = true;
        meta_reset->set_bool_attribute(ID(meta_reset));
        module->fixup_ports();
	}

public:
	MetaResetWorker(RTLIL::Module *_module, bool _opt_verbose, string _opt_signame, bool _opt_nofixedname, bool is_top) {
		opt_verbose = _opt_verbose;
		opt_signame = _opt_signame;
		opt_nofixedname = _opt_nofixedname;
		create_meta_reset(_module, is_top);
	}
};

struct MetaResetPass : public Pass {
	MetaResetPass() : Pass("meta_reset", "add meta reset to all DFFs") {}

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    meta_reset\n");
		log("\n");
		log("Adds meta reset from top to all DFFs.\n");
		log("\n");
		log("Options:\n");
		log("\n");
		log("  -verbose\n");
		log("    Verbose mode.\n");
		log("\n");
		log("  -signame <signame>\n");
		log("    Name of the meta reset signal. By default, `metaReset`.\n");
		log("\n");
		log("  -nofixedname\n");
		log("    Use the same name at all hierarchy levels.\n");
	}

	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		bool opt_verbose = false;
		bool opt_nofixedname = false;
		string opt_signame = "metaReset";

		std::vector<std::string>::size_type argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "-verbose") {
				opt_verbose = true;
				continue;
			}
			if (args[argidx] == "-signame") {
				opt_signame = args[++argidx];
				continue;
			}
			if (args[argidx] == "-nofixedname") {
				opt_nofixedname = true;
				continue;
			}
		}

		log_header(design, "Executing meta_reset pass.\n");

		if (GetSize(design->selected_modules()) == 0)
			log_cmd_error("Can't operate on an empty selection!\n");

		if(design->top_module() == NULL){
			log_cmd_error("Can't operate without top module selected! Run hierarchy -top [top_module]!\n");
		}


		// Modules must be taken in inverted topological order to instrument the deepest modules first.
		// Taken from passes/techmap/flatten.cc
		TopoSort<RTLIL::Module*, IdString::compare_ptr_by_name<RTLIL::Module>> topo_modules;
		auto worklist = design->selected_modules();
		while (!worklist.empty()) {
			RTLIL::Module *module = *(worklist.begin());
			worklist.erase(worklist.begin());
			topo_modules.node(module);

			for (auto cell : module->selected_cells()) {
				RTLIL::Module *tpl = design->module(cell->type);
				if (tpl != nullptr) {
					if (topo_modules.get_database().count(tpl) == 0)
						worklist.push_back(tpl);
					topo_modules.edge(tpl, module);
				}
			}
		}
		if (!topo_modules.sort())
			log_cmd_error("Recursive modules are not supported by meta_reset.\n");

		// Run the worker on each module.
		RTLIL::Module *top_module = design->top_module();

		for (auto &module: topo_modules.sorted) {
			MetaResetWorker(module, opt_verbose, opt_signame, opt_nofixedname, module==top_module);
		}
	}
} MetaResetPass;

PRIVATE_NAMESPACE_END
