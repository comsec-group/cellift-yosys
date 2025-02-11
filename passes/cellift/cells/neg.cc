#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"
#include "kernel/yosys.h"

USING_YOSYS_NAMESPACE
extern std::vector<RTLIL::SigSpec> get_corresponding_taint_signals(RTLIL::Module* module, std::vector<string> *excluded_signals, const RTLIL::SigSpec &sig, unsigned int num_taints);

/**
 * @param module the current module instance
 * @param cell the current cell instance
*
 * @return keep_current_cell
 */
bool cellift_neg(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals) {

    const unsigned int A = 0, Y = 1;
    const unsigned int NUM_PORTS = 2;
    RTLIL::SigSpec ports[NUM_PORTS] = {cell->getPort(ID::A), cell->getPort(ID::Y)};
    std::vector<RTLIL::SigSpec> port_taints[NUM_PORTS];

    for (unsigned int i = 0; i < NUM_PORTS; ++i)
        port_taints[i] = get_corresponding_taint_signals(module, excluded_signals, ports[i], num_taints);

    int a_size = ports[A].size();
    int y_size = ports[Y].size();

    RTLIL::SigSpec extended_a(ports[A]);

    if (a_size == y_size) {
        extended_a = ports[A];
    }
    else if (a_size < y_size) {
        bool is_a_signed = cell->getParam(ID::A_SIGNED).as_bool();
        if (!is_a_signed) {
            extended_a.append(RTLIL::SigSpec(RTLIL::State::S0, y_size-a_size));
        } else {
            RTLIL::SigBit curr_msb = ports[A][a_size-1];
            extended_a.append(RTLIL::SigSpec(curr_msb, y_size-a_size));
        }
    } else {
        extended_a = ports[A].extract(0, y_size-1);
    }

    for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++) {
        RTLIL::SigSpec extended_a_taint(port_taints[A][taint_id]);

        if (a_size == y_size) {
            extended_a_taint = port_taints[A][taint_id];
        }
        else if (a_size < y_size) {
            bool is_a_signed = cell->getParam(ID::A_SIGNED).as_bool();
            if (!is_a_signed) {
                extended_a_taint.append(RTLIL::SigSpec(RTLIL::State::S0, y_size-a_size));
            } else {
                RTLIL::SigBit curr_msb_taint = port_taints[A][taint_id][a_size-1];
                extended_a_taint.append(RTLIL::SigSpec(curr_msb_taint, y_size-a_size));
            }
        } else {
            extended_a_taint = port_taints[A][taint_id].extract(0, y_size-1);
        }

        RTLIL::SigSpec not_a_taint = module->Not(NEW_ID, extended_a_taint);
        RTLIL::SigSpec a_and_not_a_taint = module->And(NEW_ID, extended_a, not_a_taint);
        RTLIL::SigSpec a_or_a_taint = module->Or(NEW_ID, extended_a, extended_a_taint);

        RTLIL::SigSpec neg_a_and_not_a_taint = module->Neg(NEW_ID, a_and_not_a_taint);
        RTLIL::SigSpec neg_a_or_a_taint = module->Neg(NEW_ID, a_or_a_taint);

        RTLIL::SigSpec xor_out_toggled = module->Xor(NEW_ID, neg_a_and_not_a_taint, neg_a_or_a_taint);
        module->addOr(NEW_ID, xor_out_toggled, extended_a_taint, port_taints[Y][taint_id]);
    }
    return true;
}