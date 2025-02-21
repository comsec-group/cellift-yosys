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
 *  This pass marks reset wires s.t. multiplexers who are controlled by these are excluded from coverage.
 *  First, the global reset wire of the top module is identifed. Subsequently all wires that are directly connected to
 *  reset are marked as reset wires. Then, recursively, for all cells in the module it is checked whether they are
 *  a submodule. If that's the case, all wires within the submodule that are connected to a reset wire in the
 *  higher level module are marked as reset wires and so on. If the -shallow option is enabled, only the top module is considered.
 */

#include "kernel/log.h"
#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/sigtools.h"
#include "kernel/utils.h"
#include "kernel/yosys.h"

#include <algorithm>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

struct MarkResetsWorker {
      private:
	bool opt_verbose;
	RTLIL::Module *module;
	RTLIL::Design *design;
	void mark_resets_cell(RTLIL::Cell *cell, RTLIL::Module *tpl)
	{
		for (auto &port_it : cell->connections()) {
			if (!port_it.second.is_wire())
				continue;
			RTLIL::Wire *tpl_wire = tpl->wire(port_it.first);
			if (!tpl_wire->port_output && tpl_wire->port_input) {
				if (port_it.second.as_wire()->has_attribute(ID(reset_wire))) {
					tpl_wire->set_bool_attribute(ID(reset_wire));
					log("Marking %s\n in cell %s\n", tpl_wire->name.c_str(), cell->name.c_str());
					this->n_mark++;
				}
			}
		}
	}
	void mark_resets_module()
	{
		if (!design->selected(module))
			return;

		for (auto &port_it : module->connections()) {
			if (!port_it.first.is_wire() || !port_it.second.is_wire())
				continue;
			if (port_it.first.as_wire()->has_attribute(ID(reset_wire))) {
				port_it.second.as_wire()->set_bool_attribute(ID(reset_wire));
				log("Marked %s from %s in module %s!\n", port_it.second.as_wire()->name.c_str(),
				    port_it.first.as_wire()->name.c_str(), module->name.c_str());
				n_mark++;
			} else if (port_it.second.as_wire()->has_attribute(ID(reset_wire))) {
				port_it.first.as_wire()->set_bool_attribute(ID(reset_wire));
				log("Marked %s from %s in module %s!\n", port_it.first.as_wire()->name.c_str(),
				    port_it.second.as_wire()->name.c_str(), module->name.c_str());
				n_mark++;
			}
		}
		std::vector<RTLIL::Cell *> worklist = module->selected_cells();
		while (!worklist.empty()) {
			RTLIL::Cell *cell = worklist.back();
			worklist.pop_back();
			if (!design->has(cell->type))
				continue;

			RTLIL::Module *tpl = design->module(cell->type);
			mark_resets_cell(cell, tpl);
		}
	}

      public:
	int n_mark = 0;
	MarkResetsWorker(RTLIL::Module *module, bool _opt_verbose, RTLIL::Design *design)
	{
		opt_verbose = _opt_verbose;
		this->module = module;
		this->design = design;
		mark_resets_module();
	}
};

RTLIL::Wire *find_reset(RTLIL::Module *module)
{
	for (auto wire : module->wires()) {
		if (!strcmp(RTLIL::id2cstr(wire->name), "rst_ni") || !strcmp(RTLIL::id2cstr(wire->name), "reset") ||
		    !strcmp(RTLIL::id2cstr(wire->name), "reset_wire_reset") || !strcmp(RTLIL::id2cstr(wire->name), "g_resetn") ||
		    !strcmp(RTLIL::id2cstr(wire->name), "resetn") || !strcmp(RTLIL::id2cstr(wire->name), "rstz")) {
			log("Found reset wire %s in top module %s\n", wire->name.c_str(), module->name.c_str());
			return wire;
		}
	}
	log_error("Could not find reset wire in top module %s\n", module->name.c_str());
	return NULL;
}

struct MarkResetsPass : public Pass {
	MarkResetsPass() : Pass("mark_resets", "mark all wires connected to top reset wire") {}

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    mark_resets <command> [options] [selection]\n");
		log("\n");
		log("Marks reset wires to skip in mux_probes pass.\n");
		log("\n");
		log("Options:\n");
		log("\n");
		log("  -verbose\n");
		log("    Verbose mode.\n");
	}

	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		bool opt_verbose = false;
		bool opt_shallow = false;

		std::vector<std::string>::size_type argidx;
		for (argidx = 1; argidx < args.size(); argidx++) {
			if (args[argidx] == "-verbose") {
				opt_verbose = true;
				continue;
			}
			if (args[argidx] == "-shallow") {
				opt_shallow = true;
				continue;
			}
		}

		log_header(design, "Executing mark_resets pass.\n");

		if (GetSize(design->selected_modules()) == 0) {
			log_cmd_error("Can't operate on an empty selection!\n");
		}

		if (design->top_module() == NULL) {
			log_cmd_error("Can't operate without top module selected! Run hierarchy -top [topmodule]!\n");
		}

		// Modules must be taken in inverted topological order to instrument the deepest modules first.
		// Taken from passes/techmap/flatten.cc
		TopoSort<RTLIL::Module *, IdString::compare_ptr_by_name<RTLIL::Module>> topomodules;
		auto worklist = design->selected_modules();
		while (!worklist.empty()) {
			RTLIL::Module *module = *(worklist.begin());
			worklist.erase(worklist.begin());
			topomodules.node(module);

			for (auto cell : module->selected_cells()) {
				RTLIL::Module *tpl = design->module(cell->type);
				if (tpl != nullptr) {
					if (topomodules.get_database().count(tpl) == 0)
						worklist.push_back(tpl);
					topomodules.edge(tpl, module);
				}
			}
		}
		if (!topomodules.sort())
			log_cmd_error("Recursive modules are not supported by mux_probes.\n");

		RTLIL::Module *top_module = design->top_module();
		RTLIL::Wire *top_reset = find_reset(top_module);
		top_reset->set_bool_attribute(ID(reset_wire));
		int total_count = 1;
		if (opt_shallow) {
			log("Running shallow (only ignore MUX select signals connected to top module reset)\n");
			MarkResetsWorker worker = MarkResetsWorker(design->top_module(), opt_verbose, design);
			total_count += worker.n_mark;
		} else {
			for (auto i = GetSize(topomodules.sorted) - 1; i >= 0; --i) {
				RTLIL::Module *module = topomodules.sorted[i];
				MarkResetsWorker worker = MarkResetsWorker(module, opt_verbose, design);
				total_count += worker.n_mark;
			}
		}
		log("Marked %i reset wires in total.\n", total_count);
	}
} MarkResetsPass;

PRIVATE_NAMESPACE_END
