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

typedef enum {
    SHIFT_TYPE,
	SHIFTX_TYPE,
	SHL_TYPE,
	SHR_TYPE,
	SSHL_TYPE,
	SSHR_TYPE
} shift_cell_t;

struct StatShiftOffsetsWorker {
private:
	bool opt_shift_ports;
	bool opt_cell_ports;

	const std::string stat_shift_offsets_attr_name = ID(stat_shift_offsets).str();

	// Cannot use dict because the key is not hashable
	std::map<unsigned long, unsigned long> shift_cell_offsets[6];
	const std::string shift_cell_names[6] = {"$shift",
		"$shiftx",
		"$shl",
		"$shr",
		"$sshl",
		"$sshr"
	};

	/////////////////////////////
	// Main recursive function //
	/////////////////////////////

	/**
	 * @param module the current module.
	 */
	void stat_stat_shift_offsets (RTLIL::Module *module) {		
		for (RTLIL::Cell *cell: module->cells()) {
			RTLIL::Module *submodule = module->design->module(cell->type);
			// If this is an elementary cell.
			if (submodule == nullptr) {
				unsigned int shift_cell_offset;
				for (int i = 0; i < 6; i++) {
					if (cell->type.str() == shift_cell_names[i]) {
						shift_cell_offset = cell->getParam(ID(B_WIDTH)).as_int();
						if (shift_cell_offsets[i].find(shift_cell_offset) == shift_cell_offsets[i].end()) {
							shift_cell_offsets[i][shift_cell_offset] = 1;
						} else {
							shift_cell_offsets[i][shift_cell_offset]++;
						}

						log("Found a shift (%s) of width %u in module %s\n", shift_cell_names[i].c_str(), shift_cell_offset, module->name.c_str());
					}
				}
			} else {
				// If this is a submodule, then apply the statistics function recursively.
				stat_stat_shift_offsets(submodule);
			}
		}
	}

	/////////////////////////////
	// Display wire pre-taints //
	/////////////////////////////

	void display_stats () {

		for (int i = 0; i < 6; i++) {
			log("Cell is %s\n", shift_cell_names[i].c_str());

			for (auto const& curr_offset : shift_cell_offsets[i]) {
				log("  %lu is %lu\n", curr_offset.first, curr_offset.second);
			}
		}
	}

public:
	StatShiftOffsetsWorker(RTLIL::Module *top_module) {
		stat_stat_shift_offsets(top_module);

		display_stats();
	}
};

struct StatShiftOffsetsPass : public Pass {
	StatShiftOffsetsPass() : Pass("stat_shift_offsets", "Makes statistics for the shift cells offsets.") {}

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    stat_shift_offsets <command> [options] [selection]\n");
		log("\n");
		log("Makes statistics for the shift cells offsets.\n");
		log("\n");
	}

	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Executing stat_shift_offsets pass (statistics for shift offsets).\n");

		if (GetSize(design->selected_modules()) == 0)
			log_cmd_error("Can't operate on an empty selection!\n");

		StatShiftOffsetsWorker worker(design->top_module());
	}
} StatShiftOffsetsPass;

PRIVATE_NAMESPACE_END
