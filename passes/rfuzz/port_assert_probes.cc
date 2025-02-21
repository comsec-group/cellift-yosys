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
 *  This pass concatenates the assert wires to a SigSpec to form a port. This
 *  is required by the harness generator.
 */


#include "kernel/yosys.h"
#include "kernel/log.h"
#include "kernel/rtlil.h"

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN


static int count_assert_wires(RTLIL::Module *module){
    int count = 0;
	for (auto &wire_iter : module->wires_)
		if(wire_iter.second->has_attribute(ID(assert_wire))) count++;
	
	return count;
}

static void gen_assert_port( RTLIL::Design *design, bool opt_verbose){
	RTLIL::Module *module = design->top_module();
	int n_assert_wires = count_assert_wires(module);
	// Ensure that there are assert wires, else we would create ugly and useless ports looking like this: output [-1:0] assert_out;
	if (!n_assert_wires) {
		log("No assert wire found. Not creating the assert port.\n");
		return;
	}

	log("Creating port for %i assert wires\n", n_assert_wires);
	RTLIL::SigSpec assert_wires = SigSpec();
    for (auto &wire_iter : module->wires_){
		RTLIL::Wire *wire = wire_iter.second;

		if (!design->selected(module, wire))
			continue;

        if(wire->has_attribute(ID(assert_wire))){
            if(opt_verbose) log("Adding assert signal %s to port\n", RTLIL::id2cstr(wire->name));
			assert_wires.append(wire);
			wire->port_output = false;
        }
    }
	RTLIL::Wire *assert_port = module->addWire("\\assert_out", n_assert_wires);
	assert_port->set_bool_attribute(ID(assert_wire));
	module->connect(assert_port,assert_wires);
	assert_port->port_output = true;
	assert_port->set_bool_attribute(ID(port));
	module->fixup_ports();

}
struct PortAssertProbesPass : public Pass {
	PortAssertProbesPass() : Pass("port_assert_probes") { }

	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    port_assert_probes\n");
		log("\n");
		log("Creates port for assert probes.\n");
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

		log_header(design, "Executing port_assert_probes pass (Concat assert probe signals to form port).\n");
		gen_assert_port(design, opt_verbose);           
				
	}
} PortAssertProbesPass;

PRIVATE_NAMESPACE_END
