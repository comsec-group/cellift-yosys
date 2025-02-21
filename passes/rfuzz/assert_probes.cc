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
 *  This pass is analogous to the mux_probes pass. However, it identifies assert cells and wires the corresponding
 *  assert signal to top while removing the assertion cells themselves s.t. execution is not aborted when an assertion
 *  is violated. 
 */


#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"
#include "kernel/yosys.h"

#include <algorithm>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

struct AssertProbesWorker {
private:
	// Command line arguments.
	bool opt_verbose;

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

	int create_assert_probes(RTLIL::Module *module) {
		int count = 0;

		if (opt_verbose)
			log("Creating assert probes for module %s.\n", module->name.c_str());

		if (module->processes.size())
			log_error("Unexpected process. Requires a `proc` pass before.\n");

		for(std::pair<RTLIL::IdString, RTLIL::Cell*> cell_pair : module->cells_) {
			RTLIL::IdString cell_name = cell_pair.first;
			RTLIL::Cell *cell = cell_pair.second;

			if(cell->type.in(ID($assert))) { // find assert cells
				RTLIL::SigSpec port_q(cell->getPort(ID::A)); // get assert signals
				for (auto &chunk_it: port_q.chunks()) {
					if (!chunk_it.is_wire()) continue; // skip constants
					std::string wire_name = string(chunk_it.wire->name.c_str());       
            		
					wire_name = "__ASSERT_"+cell->name.str()+"__WIRE_"+chunk_it.wire->name.str();
					wire_name = sanitize_wire_name(wire_name);
					if (opt_verbose)
						log("Adding wire %s from assert in module %s: %s\n", chunk_it.wire->name.c_str(), module->name.c_str(), wire_name.c_str());

					Wire *new_wire = module->addWire(wire_name, chunk_it.width);

					// connect wire to assert condition s.t. 1 ^= violated, from ./passes/sat/miter.cc:318
					module->addNex(NEW_ID, cell->getPort(ID::A), State::S1, new_wire); 

					count++;

					new_wire->port_output = true;
					new_wire->set_bool_attribute(ID(assert_wire)); // mark as assert wire

				}
				module->remove(cell); // remove assert cell
			}

			else if (module->design->module(cell->type) != nullptr) { // is cell a submodule?
				RTLIL::Module *submodule = module->design->module(cell->type);
				for (Wire *submodule_wire: submodule->wires()) {
					if (submodule_wire->has_attribute(ID(assert_wire))) {
						std::string wire_name;
						wire_name = submodule->name.c_str() + std::string("-") + cell->name.c_str() + "_" +submodule_wire->name.str();
						wire_name = sanitize_wire_name(wire_name);
						if (opt_verbose)
							log("Adding wire to module %s from submodule %s: %s\n", module->name.c_str(), submodule->name.c_str(), wire_name.c_str());
						Wire *new_wire = module->addWire(wire_name, submodule_wire->width);
						cell->setPort(submodule_wire->name.str(), new_wire);
						new_wire->port_output = true;
						new_wire->set_bool_attribute(ID(assert_wire));
						submodule->fixup_ports();
					}
				}
			}
		}
		module->fixup_ports();
		module->set_bool_attribute(ID(assert_probes), true);
		log("Probed %i asserts in module %s.\n", count, RTLIL::id2cstr(module->name));
		return count;

	}

public:
	int n_assert = 0;
	AssertProbesWorker(RTLIL::Module *_module, bool _opt_verbose) {
		opt_verbose = _opt_verbose;
		this->n_assert = create_assert_probes(_module);
	}
};

struct AssertProbesPass : public Pass {
	AssertProbesPass() : Pass("assert_probes", "create probe wires to all assert cells") {}

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    assert_probes <command> [options] [selection]\n");
		log("\n");
		log("Creates assert probes reaching the design toplevel.\n");
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

		log_header(design, "Executing assert_probes pass.\n");

		if (GetSize(design->selected_modules()) == 0)
			log_cmd_error("Can't operate on an empty selection!\n");

		// Check whether some module is selected.
		if (GetSize(design->selected_modules()) == 0)
			log_cmd_error("assert_probes cannot operate on an empty.\n");

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
			log_cmd_error("Recursive modules are not supported by assert_probes.\n");

		// Run the worker on each module.
		int total_count = 0;
		for (auto i = 0; i < GetSize(topo_modules.sorted); ++i) {
			RTLIL::Module *module = topo_modules.sorted[i];
			AssertProbesWorker worker = AssertProbesWorker(module, opt_verbose);
			total_count += worker.n_assert;
		}
		log("Probed %i assert cells in total.\n", total_count);

	}
} AssertProbesPass;

PRIVATE_NAMESPACE_END
