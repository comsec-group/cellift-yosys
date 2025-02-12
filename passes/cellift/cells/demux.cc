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
bool cellift_demux(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals) {

    const unsigned int A = 0, S = 1, Y = 2;
    const unsigned int NUM_PORTS = 3;
    RTLIL::SigSpec ports[NUM_PORTS] = {cell->getPort(ID::A), cell->getPort(ID::S), cell->getPort(ID::Y)};
    std::vector<RTLIL::SigSpec> port_taints[NUM_PORTS];

    for (unsigned int i = 0; i < NUM_PORTS; ++i)
        port_taints[i] = get_corresponding_taint_signals(module, excluded_signals, ports[i], num_taints);

    unsigned int a_size = ports[A].size();
    unsigned int s_size = ports[S].size();
    unsigned int y_size = ports[Y].size();

    unsigned int data_width = cell->getParam(ID::WIDTH).as_int(false);
    unsigned int expected_a_size = data_width * (1ULL << s_size);

    unsigned int s_width_param = cell->getParam(ID::S_WIDTH).as_int(false);
    if (s_size != s_width_param) {
        log("S size: %d, S_WIDTH param: %d.\n", s_size, s_width_param);
        log_cmd_error("In $demux, the size of the S port must match the S_WIDTH parameter.\n");
    }

    RTLIL::SigSpec extended_a(ports[A]);

    if (a_size == expected_a_size) {
        extended_a = ports[A];
    }
    else if (a_size < expected_a_size) {
        extended_a.append(RTLIL::SigSpec(RTLIL::State::S0, expected_a_size-a_size));
    } else {
        extended_a = ports[A].extract(0, expected_a_size-1);
    }

    unsigned int expected_y_taint_size = data_width * (1ULL << s_size);

    for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++) {
        // Extend and slice the Y taints
        RTLIL::SigSpec extended_y_taint(port_taints[Y][taint_id]);
        if (y_size == expected_y_taint_size) {
            extended_y_taint = port_taints[Y][taint_id];
        }
        else if (y_size < expected_y_taint_size) {
            extended_y_taint.append(RTLIL::SigSpec(RTLIL::State::S0, expected_y_taint_size-y_size));
        } else {
            extended_y_taint = port_taints[Y][taint_id].extract(0, expected_y_taint_size-1);
        }
        std::vector<RTLIL::SigSpec> y_taint_slices;
        for (unsigned int i = 0; i < (1ULL << s_size); i++) {
            log("Extracting bits at index %d, width %d. Total size: %d.\n", i*data_width, data_width, extended_y_taint.size());
            y_taint_slices.push_back(extended_y_taint.extract(i*data_width, data_width));
        }

        RTLIL::SigSpec or_reduce_s_taint_output = module->ReduceOr(NEW_ID, port_taints[S][taint_id]);

        std::vector<RTLIL::SigBit> is_s_equality_tainted;
        std::vector<RTLIL::SigBit> is_s_equality_true;

        // Compute `is_s_equality_tainted`
        RTLIL::SigSpec not_s_taint = module->Not(NEW_ID, port_taints[S][taint_id]);
        RTLIL::SigSpec s_non_tainted_input_vals = module->And(NEW_ID, ports[S], not_s_taint);
        for (unsigned int candidate_s_value = 0; candidate_s_value < (1ULL << s_size); candidate_s_value++) {
            // Check whether the non_tainted bits match: mask out the tainted values and compare.
            RTLIL::SigSpec candidate_s_sig = RTLIL::SigSpec(candidate_s_value, s_size);
            RTLIL::SigSpec a_non_tainted_input_vals = module->And(NEW_ID, candidate_s_sig, not_s_taint);
            RTLIL::SigSpec are_non_tainted_bits_equal = module->Eq(NEW_ID, a_non_tainted_input_vals, s_non_tainted_input_vals);

            is_s_equality_tainted.push_back(module->And(NEW_ID, are_non_tainted_bits_equal, or_reduce_s_taint_output));
        }

        // Compute `is_s_equality_true`
        for (unsigned int candidate_s_value = 0; candidate_s_value < (1ULL << s_size); candidate_s_value++) {
            RTLIL::SigSpec candidate_s_sig = RTLIL::SigSpec(candidate_s_value, s_size);
            RTLIL::SigSpec are_bits_equal = module->Eq(NEW_ID, ports[S], candidate_s_sig);
            is_s_equality_true.push_back(are_bits_equal);
        }

        RTLIL::SigSpec extended_a_taint(port_taints[A][taint_id]);

        if (a_size == expected_a_size) {
            extended_a_taint = port_taints[A][taint_id];
        }
        else if (a_size < expected_a_size) {
            extended_a_taint.append(RTLIL::SigSpec(RTLIL::State::S0, expected_a_size-a_size));
        } else {
            extended_a_taint = port_taints[A][taint_id].extract(0, expected_a_size-1);
        }


        for (unsigned int candidate_s_value = 0; candidate_s_value < (1ULL << s_size); candidate_s_value++) {
            RTLIL::SigBit can_s_reach_candidate_s_value = module->Or(NEW_ID, is_s_equality_tainted[candidate_s_value], is_s_equality_true[candidate_s_value]);

            // Implicit propagation, relatively basic because we multiplex between A and zero.
            RTLIL::SigSpec implicit_taint = module->And(NEW_ID, extended_a, RTLIL::SigSpec(is_s_equality_tainted[candidate_s_value], expected_a_size));

            // Explicit propagation
            RTLIL::SigSpec explicit_taint = module->And(NEW_ID, extended_a_taint, RTLIL::SigSpec(can_s_reach_candidate_s_value, expected_a_size));

            module->addOr(NEW_ID, implicit_taint, explicit_taint, y_taint_slices[candidate_s_value]);
        }
    }
    return true;
}