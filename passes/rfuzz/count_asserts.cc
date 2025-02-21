#include "kernel/yosys.h"
#include "kernel/log.h"
#include "kernel/rtlil.h"

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN




static int count_asserts(RTLIL::Module *module){
    int count = 0;
    for(auto &cell : module->cells().to_vector()) {
        if(cell->type.in(ID($assert))) count++;
    }
    log("Found %i asserts in module %s.\n", count,RTLIL::id2cstr(module->name));
	return count;
}
struct CountAssertsPass : public Pass {
	CountAssertsPass() : Pass("count_asserts") { }
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
		log_header(design, "Executing count_asserts pass (count asserts in design).\n");

		// selected as a whole or contains selected objects.
		int total_count = 0;
		for (auto &it : design->modules_)
			if (design->selected_module(it.first))
				total_count += count_asserts(it.second);

		log("Found %i asserts in total.\n", total_count);

	}
} StubnetsPass;

PRIVATE_NAMESPACE_END
