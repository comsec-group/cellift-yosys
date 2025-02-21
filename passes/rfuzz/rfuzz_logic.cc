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
 *  This pass adds the rfuzz logic to each multiplexer. That is, for each multiplexer, two additional multiplexer
 *  and two FFs are added. The state of these FFs then indicates whether the instrumented multiplexer toggled during
 *  test applciation. The possible states are 
 *  - {0,1}: the select signal was constantly 0
 *  - {1,0}: the select signal was constantly 1
 *  - {1,1}: the select signal was both 0 and 1 i.e. a toggle occured
 *  This pass is currently not used as the harness adds this logic. However, the pass might be helpful for future use.
 */



#include "kernel/yosys.h"
#include "kernel/log.h"
#include "kernel/rtlil.h"

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN
#define NUM_PORTS 3


static int add_regs_to_mux(RTLIL::Module *module){  //only for 1-bit mux, apply pmuxtree before
    int count = 0;
	RTLIL::SigBit clk_sig;
	int found_clk = 0;
    for(auto &cell : module->cells().to_vector()) {
		if(!found_clk){
			if(cell->type.in(ID($anyinit), ID($ff), ID($dff), ID($dffe), ID($dffsr), ID($dffsre), ID($adff), ID($adffe), ID($aldff), ID($aldffe), ID($sdff), ID($sdffe), ID($sdffce), ID($dlatch), ID($adlatch), ID($dlatchsr), ID($sr))) {
				found_clk = 1;
				clk_sig = cell->getPort(ID::CLK);
				log("Found clock signal\n");
			} 	
		}
        if(cell->type.in(ID($mux), ID($_MUX_), ID($_NMUX_))) {// find MUX
			count++;
			RTLIL::SigSpec tmux_ports[NUM_PORTS] = {cell->getPort(ID::A), cell->getPort(ID::B), cell->getPort(ID::S)};

			// detects a 0
			RTLIL::Wire *wire0 = module->addWire(NEW_ID);
			RTLIL::SigSpec mux0_out = module->Mux(NEW_ID, RTLIL::SigBit(1),RTLIL::SigBit(wire0), tmux_ports[2]);
			RTLIL::Cell *dff0 = module->addDff(NEW_ID,clk_sig, mux0_out, RTLIL::SigBit(wire0));
			dff0->set_bool_attribute(ID(cov_ff));

			// detects a 1
			RTLIL::Wire *wire1 = module->addWire(NEW_ID);
			RTLIL::SigSpec mux1_out = module->Mux(NEW_ID,RTLIL::SigBit(wire1), RTLIL::SigBit(1), tmux_ports[2]);
			RTLIL::Cell *dff1 = module->addDff(NEW_ID,clk_sig, mux1_out, RTLIL::SigBit(wire1));
			dff0->set_bool_attribute(ID(cov_ff));

			//if mux select toggled, both DFFs should hold 1s
		}

    }
    log("Instrumented %i muxltiplexers in module %s.\n", count,RTLIL::id2cstr(module->name));
	return count;
}
struct RfuzzPass : public Pass {
	RfuzzPass() : Pass("rfuzz") { }
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Executing rfuzz pass.\n");
		int total_count = 0;
		// selected as a whole or contains selected objects.
		for (auto &it : design->modules_)
			if (design->selected_module(it.first))
				total_count += add_regs_to_mux(it.second);

		log("Instrumented %i muxltiplexers in total.\n", total_count);

	}
} StubnetsPass;

PRIVATE_NAMESPACE_END
