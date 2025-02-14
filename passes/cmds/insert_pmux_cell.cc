/*
 *  yosys -- Yosys Open SYnthesis Suite
 *
 *  Copyright (C) 2020  Alberto Gonzalez <boqwxp@airmail.cc> & Flavien Solt <flsolt@ethz.ch>
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
 */

#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"
#include "kernel/yosys.h"

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

struct InsertPmuxCellWorker {
private:
	RTLIL::Module *module = nullptr;
	bool is_multiple = false;
	const RTLIL::IdString insert_pmux_cell_attribute_name = ID(insert_pmux_cell);

	void insert_pmux_cell() {

		if (module->get_bool_attribute(insert_pmux_cell_attribute_name))
			return;

		log("Inserting pmux cell...\n");

		std::vector<RTLIL::Wire*> wires(module->wires());
		std::vector<RTLIL::Cell*> cells(module->cells());

		// log("Removed original cells.\n");
		// while (cells.size() > 0 && cells[0]->type != ID($dummy)) {
		// 	module->remove(cells[0]);
		// }
		// log("Removed original cells.\n");

		int multiple_id = 0;
		do {
			RTLIL::Wire* wire_a_i = NULL;
			RTLIL::Wire* wire_b_i = NULL;
			RTLIL::Wire* wire_s_i = NULL;
			RTLIL::Wire* wire_y_o = NULL;

			std::string wire_a_i_name;
			std::string wire_b_i_name;
			std::string wire_s_i_name;
			std::string wire_y_o_name;

			if (is_multiple) {
				wire_a_i_name = stringf("a_i_%d", multiple_id);
				wire_b_i_name = stringf("b_i_%d", multiple_id);
				wire_s_i_name = stringf("s_i_%d", multiple_id);
				wire_y_o_name = stringf("y_o_%d", multiple_id);
			} else {
				wire_a_i_name = "a_i";
				wire_b_i_name = "b_i";
				wire_s_i_name = "s_i";
				wire_y_o_name = "y_o";
			}

			for(unsigned int i = 0; i < wires.size(); i++) {
				if (wires[i]->name == RTLIL::escape_id(wire_a_i_name))
					wire_a_i = wires[i];
				else if (wires[i]->name == RTLIL::escape_id(wire_b_i_name))
					wire_b_i = wires[i];
				else if (wires[i]->name == RTLIL::escape_id(wire_s_i_name))
					wire_s_i = wires[i];
				else if (wires[i]->name == RTLIL::escape_id(wire_y_o_name))
					wire_y_o = wires[i];
			}

			if (wire_a_i == NULL || wire_b_i == NULL || wire_s_i == NULL || wire_y_o == NULL) {
				if (is_multiple) {
					if (multiple_id == 0) {
						log_cmd_error("Missing wires in the module (currently running with `-multiple` flag).\n");
					} else {
						break;
					}
				}
				if (!is_multiple) {
					if (wire_a_i == NULL) {
						log("Missing wire a_i.\n");
					}
					if (wire_b_i == NULL) {
						log("Missing wire b_i.\n");
					}
					if (wire_s_i == NULL) {
						log("Missing wire s_i.\n");
					}
					if (wire_y_o == NULL) {
						log("Missing wire y_o.\n");
					}
					log_cmd_error("Missing wires in the module.\n");
				}
			}

			RTLIL::Cell* new_cell;
			RTLIL::Const rst_val_sigspec;

			new_cell = module->addPmux(NEW_ID, wire_a_i, wire_b_i, wire_s_i, wire_y_o);
			for (auto &param: module->parameter_default_values)
				new_cell->setParam(param.first, param.second);

			for (auto &param: new_cell->parameters) {
				log("New cell param: %s = %d\n", param.first.c_str(), param.second.as_int());
			}

			module->set_bool_attribute(insert_pmux_cell_attribute_name, true);
			multiple_id++;
		} while (is_multiple);
	}

public:
	InsertPmuxCellWorker(RTLIL::Module *_module, bool _is_multiple) {
		module = _module;
		is_multiple = _is_multiple;
		insert_pmux_cell();
	}
};

struct InsertPmuxCellPass : public Pass {
	InsertPmuxCellPass() : Pass("insert_pmux_cell", "Add a pmux cell in the design top module. This is a pass dedicated to cell unit testing.") {}

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    insert_pmux_cell --multiple\n");
		log("\n");
		log("Add a pmux cell in each module of the design.\n");
		log("This pass has been designed for testing the pmux implementation.\n");
		log("The top module must contain exactly one dummy cell.\n");
		log("	-multiple: instead of looking for a_i, etc., will look for a_i_0, a_i_1, etc. until not finding them anymore\n");
		log("\n");
	}

	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Executing insert_pmux_cell pass.\n");

		bool is_multiple = false;
		std::vector<std::string>::size_type argidx;

		for (argidx = 1; argidx < args.size(); argidx++)
			if (args[argidx] == "-multiple")
				is_multiple = true;

		if (GetSize(design->selected_modules()) == 0)
			log_cmd_error("Can't operate on an empty selection!\n");

		InsertPmuxCellWorker worker(design->top_module(), is_multiple);
	}
} InsertPmuxCellPass;

PRIVATE_NAMESPACE_END
