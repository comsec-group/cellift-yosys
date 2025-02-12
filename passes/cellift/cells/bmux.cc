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
bool cellift_bmux(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals) {

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

    std::vector<RTLIL::SigSpec> a_slices;
    for (unsigned int i = 0; i < (1ULL << s_size); i++) {
        a_slices.push_back(extended_a.extract(i*data_width, data_width));
    }

    for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++) {
        RTLIL::SigSpec or_reduce_s_taint_output = module->ReduceOr(NEW_ID, port_taints[S][taint_id]);

        std::vector<RTLIL::SigBit> is_s_equality_tainted;

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

        std::vector<RTLIL::SigBit> is_s_equality_true_or_tainted;
        // Compute `is_s_equality_true_or_tainted`
        for (unsigned int candidate_s_value = 0; candidate_s_value < (1ULL << s_size); candidate_s_value++) {
            RTLIL::SigSpec candidate_s_sig = RTLIL::SigSpec(candidate_s_value, s_size);
            RTLIL::SigSpec are_bits_equal = module->Eq(NEW_ID, ports[S], candidate_s_sig);
            // is_s_equality_true.push_back(module->ReduceOr(NEW_ID, are_bits_equal));
            is_s_equality_true_or_tainted.push_back(module->Or(NEW_ID, are_bits_equal, is_s_equality_tainted[candidate_s_value]));
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
        std::vector<RTLIL::SigSpec> a_taint_slices;
        for (unsigned int i = 0; i < (1ULL << s_size); i++) {
            a_taint_slices.push_back(extended_a_taint.extract(i*data_width, data_width));
        }

        std::vector<RTLIL::SigSpec> implicit_prerotate; // eventualy should have size 1 << s_size
        std::vector<RTLIL::SigSpec> explicit_prereduce;

        for (unsigned int candidate_s_value = 0; candidate_s_value < (1ULL << s_size); candidate_s_value++) {
            // Implicit flows: Taints coming from the data input port.
            implicit_prerotate.push_back(module->Mux(NEW_ID, ports[Y], a_slices[candidate_s_value], is_s_equality_tainted[candidate_s_value]));
            // Explicit flows: Taints coming from the selectable entries.
            explicit_prereduce.push_back(module->Mux(NEW_ID, RTLIL::SigSpec(RTLIL::State::S0, data_width), a_taint_slices[candidate_s_value], is_s_equality_true_or_tainted[candidate_s_value]));
        }

        // Reduce the implicits
        std::vector<RTLIL::SigBit> implicit_rotated_reduced;
        for (unsigned int i = 0; i < data_width; i++) {
            RTLIL::SigSpec curr_implicit_rotated;
            for (unsigned int j = 0; j < (1ULL << s_size); j++) {
                curr_implicit_rotated.append(implicit_prerotate[j][i]);
            }

            implicit_rotated_reduced.push_back(module->Ne(NEW_ID, curr_implicit_rotated, RTLIL::SigSpec(curr_implicit_rotated.extract(0, 1), curr_implicit_rotated.size())));
        }
        RTLIL::SigSpec implicit_rotated_reduced_sig(implicit_rotated_reduced); 

        // Reduce the explicits
        std::vector<RTLIL::SigSpec> explicit_rotated_reduction_sigs;
        explicit_rotated_reduction_sigs.push_back(explicit_prereduce[0]);
        for (unsigned int i = 1; i < (1ULL << s_size); i++) {
            explicit_rotated_reduction_sigs.push_back(module->Or(NEW_ID, explicit_prereduce[i], explicit_rotated_reduction_sigs[i-1]));
        }
        RTLIL::SigSpec explicit_rotated_reduced_sig = explicit_rotated_reduction_sigs.back();

        module->addOr(NEW_ID, implicit_rotated_reduced_sig, explicit_rotated_reduced_sig, port_taints[Y][taint_id]);
    }
    return true;
}