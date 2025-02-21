#include "kernel/yosys.h"
#include "kernel/log.h"
#include "kernel/rtlil.h"

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN




static int count_mux(RTLIL::Module *module){
    int count = 0;
    for(auto &cell : module->cells().to_vector()) {
        if(cell->type.in(ID($mux), ID($_MUX_), ID($_NMUX_))) count++;
    }
    log("Found %i muxltiplexers in module %s.\n", count,RTLIL::id2cstr(module->name));
	return count;
}
struct CountMuxPass : public Pass {
	CountMuxPass() : Pass("count_mux") { }
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Executing count_mux pass (count multiplexers in design).\n");

		// selected as a whole or contains selected objects.
		int total_count = 0;
		for (auto module : design->modules()){
			if (!design->selected_module(module->name)) continue;
			for(auto cell: module->cells()){
				if(design->module(cell->type) == nullptr) continue;
				total_count += count_mux(design->module(cell->type));
			}
		}
		total_count += count_mux(design->top_module());

			

		log("Found %i muxltiplexers in total.\n", total_count);

	}
} StubnetsPass;

PRIVATE_NAMESPACE_END
