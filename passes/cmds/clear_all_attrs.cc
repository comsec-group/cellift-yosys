// Copyright 2022 Flavien Solt, ETH Zurich.
// Licensed under the General Public License, Version 3.0, see LICENSE for details.
// SPDX-License-Identifier: GPL-3.0-only

#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"
#include "kernel/yosys.h"

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

struct ClearAllAttrsWorker {
private:

	/////////////////////////////
	// Main recursive function //
	/////////////////////////////

	/**
	 * @param module the current module.
	 * @param path_so_far the path to current module. Does not include the final separator.
	 */
	void clear_all_attrs (RTLIL::Module *module) {
		module->attributes.clear();

		for (auto curr_attrobj: module->wires())
			curr_attrobj->attributes.clear();
		for (auto curr_attr_second_pair: module->memories)
			curr_attr_second_pair.second->attributes.clear();
		for (auto curr_attr_second_pair: module->processes)
			curr_attr_second_pair.second->attributes.clear();

		for (RTLIL::Cell *cell: module->cells()) {
			RTLIL::Module *submodule = module->design->module(cell->type);
			// If this is an elementary cell.
			if (submodule == nullptr) {
				cell->attributes.clear();
			} else {
				// If this is a submodule, then apply the statistics function recursively.
				clear_all_attrs(submodule);
			}
		}
	}

public:
	ClearAllAttrsWorker(RTLIL::Module *top_module) {
		clear_all_attrs(top_module);
	}
};

struct ClearAllAttrsPass : public Pass {
	ClearAllAttrsPass() : Pass("clear_all_attrs", "Clears all attributes in the selected module and its children.") {}

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    clear_all_attrs <command> [options] [selection]\n");
		log("\n");
		log("Clears all attributes in the selected module and its children.\n");
		log("\n");
	}

	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Executing clear_all_attrs pass.\n");

		if (GetSize(design->selected_modules()) == 0)
			log_cmd_error("Can't operate on an empty selection!\n");

		ClearAllAttrsWorker worker(design->top_module());
	}
} ClearAllAttrsPass;

PRIVATE_NAMESPACE_END
