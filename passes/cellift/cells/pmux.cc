#include "kernel/rtlil.h"
#include "kernel/utils.h"
#include "kernel/log.h"
#include "kernel/yosys.h"

USING_YOSYS_NAMESPACE
extern std::vector<RTLIL::SigSpec> get_corresponding_taint_signals(RTLIL::Module* module, std::vector<string> *excluded_signals, const RTLIL::SigSpec &sig, unsigned int num_taints);

/**
 * @param module the current module instance
 * @param cell the current cell instance
 * @return keep_current_cell
 */
bool cellift_pmux(RTLIL::Module *module, RTLIL::Cell *cell, unsigned int num_taints, std::vector<string> *excluded_signals) {

    const unsigned int A = 0, B=1, S = 2, Y = 3;
    const unsigned int NUM_PORTS = 4;
    RTLIL::SigSpec ports[NUM_PORTS] = {cell->getPort(ID::A), cell->getPort(ID::B), cell->getPort(ID::S), cell->getPort(ID::Y)};
    std::vector<RTLIL::SigSpec> port_taints[NUM_PORTS];

    for (unsigned int i = 0; i < NUM_PORTS; ++i)
        port_taints[i] = get_corresponding_taint_signals(module, excluded_signals, ports[i], num_taints);

    unsigned int a_size = ports[A].size();
    unsigned int b_size = ports[B].size();
    unsigned int s_size = ports[S].size();
    // unsigned int y_size = ports[Y].size();

    unsigned int data_width = cell->getParam(ID::WIDTH).as_int(false);
    unsigned int expected_a_size = data_width;
    unsigned int expected_b_size = data_width * s_size;

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

    RTLIL::SigSpec extended_b(ports[B]);
    if (b_size == expected_b_size) {
        extended_b = ports[B];
    }
    else if (b_size < expected_b_size) {
        extended_b.append(RTLIL::SigSpec(RTLIL::State::S0, expected_b_size-b_size));
    } else {
        extended_b = ports[B].extract(0, expected_b_size-1);
    }

    std::vector<RTLIL::SigSpec> b_slices;
    for (unsigned int i = 0; i < s_size; i++) {
        b_slices.push_back(extended_b.extract(i*data_width, data_width));
    }

    for (unsigned int taint_id = 0; taint_id < num_taints; taint_id++) {
        RTLIL::SigSpec not_s = module->Not(NEW_ID, ports[S]);
        RTLIL::SigSpec are_s_bits_zero_or_tainted = module->Or(NEW_ID, not_s, port_taints[S][taint_id]);
        RTLIL::SigSpec cumul_are_lower_bits_zero_or_tainted;
        RTLIL::SigSpec cumul_are_lower_bits_zero;
        RTLIL::SigSpec cumul_is_some_lower_bit_tainted;
        cumul_are_lower_bits_zero_or_tainted.append(RTLIL::State::S1);
        cumul_are_lower_bits_zero.append(RTLIL::State::S1);
        cumul_is_some_lower_bit_tainted.append(RTLIL::State::S0);
        for (unsigned int i = 1; i < s_size; i++) {
            cumul_are_lower_bits_zero_or_tainted.append(module->And(NEW_ID, cumul_are_lower_bits_zero_or_tainted[i-1], are_s_bits_zero_or_tainted.extract(i-1, 1)));
            cumul_are_lower_bits_zero.append(module->And(NEW_ID, cumul_are_lower_bits_zero[i-1], not_s.extract(i-1, 1)));
            cumul_is_some_lower_bit_tainted.append(module->Or(NEW_ID, cumul_is_some_lower_bit_tainted[i-1], port_taints[S][taint_id].extract(i-1, 1)));
        }

        // Its minimality is tainted if the corresponding bit is tainted and all the lower bits are tainted or zero...
        // OR if the corresponding bit is 1 and some lower bit is zero and no lower bit is 1.
        RTLIL::SigSpec is_s_minimality_tainted_impl = module->And(NEW_ID, ports[S], cumul_is_some_lower_bit_tainted);
        RTLIL::SigSpec is_s_minimality_tainted_precheck = module->Or(NEW_ID, is_s_minimality_tainted_impl, port_taints[S][taint_id]);
        RTLIL::SigSpec is_s_minimality_tainted = module->And(NEW_ID, is_s_minimality_tainted_precheck, cumul_are_lower_bits_zero_or_tainted);

        RTLIL::SigSpec extended_a_taint(port_taints[A][taint_id]);
        if (a_size == expected_a_size) {
            extended_a_taint = port_taints[A][taint_id];
        }
        else if (a_size < expected_a_size) {
            extended_a_taint.append(RTLIL::SigSpec(RTLIL::State::S0, expected_a_size-a_size));
        } else {
            extended_a_taint = port_taints[A][taint_id].extract(0, expected_a_size-1);
        }

        RTLIL::SigSpec extended_b_taint(port_taints[B][taint_id]);
        if (b_size == expected_b_size) {
            extended_b_taint = port_taints[B][taint_id];
        }
        else if (b_size < expected_b_size) {
            extended_b_taint.append(RTLIL::SigSpec(RTLIL::State::S0, expected_b_size-b_size));
        } else {
            extended_b_taint = port_taints[B][taint_id].extract(0, expected_b_size-1);
        }

        std::vector<RTLIL::SigSpec> b_taint_slices;
        for (unsigned int i = 0; i < s_size; i++) {
            b_taint_slices.push_back(extended_b_taint.extract(i*data_width, data_width));
        }

        std::vector<RTLIL::SigSpec> implicit_prerotate; // eventualy should have size 1 << s_size
        std::vector<RTLIL::SigSpec> explicit_prereduce;

        RTLIL::SigSpec is_s_minimality_true_or_tainted = module->Or(NEW_ID, is_s_minimality_tainted, module->And(NEW_ID, ports[S], cumul_are_lower_bits_zero));
        for (unsigned int id_in_s = 0; id_in_s < s_size; id_in_s++) {
            // Implicit flows: Taints coming from the data input port.
            implicit_prerotate.push_back(module->Mux(NEW_ID, ports[Y], b_slices[id_in_s], is_s_minimality_tainted[id_in_s]));
            // Explicit flows: Taints coming from the selectable entries.
            // explicit_prereduce.push_back(module->Mux(NEW_ID, RTLIL::SigSpec(RTLIL::State::S0, data_width), b_taint_slices[id_in_s], is_s_minimality_true_or_tainted[id_in_s]));
            explicit_prereduce.push_back(module->And(NEW_ID, b_taint_slices[id_in_s], RTLIL::SigSpec(is_s_minimality_true_or_tainted[id_in_s], data_width)));
        }
        RTLIL::SigBit can_s_be_zero = module->ReduceAnd(NEW_ID, are_s_bits_zero_or_tainted);

        // Implicit flows from A.
        implicit_prerotate.push_back(module->Mux(NEW_ID, ports[Y], extended_a, can_s_be_zero));
        // Explicit flows from A.
        explicit_prereduce.push_back(module->Mux(NEW_ID, ports[Y], extended_a_taint, can_s_be_zero));

        // Reduce the implicits
        if (implicit_prerotate.size() != s_size+1) {
            log("implicit_prerotate.size() = %ld, s_size+1 = %d\n", implicit_prerotate.size(), s_size+1);
            log_cmd_error("implicit_prerotate.size() != s_size+1\n");
        }

        // Option 1: No rotation: AND all the implicit prereduce signals, OR them and see if it is the same
        // The AND minimizes over the implicit prereduce signals, the OR maximizes.
        std::vector<RTLIL::SigSpec> implicit_cumulative_and;
        std::vector<RTLIL::SigSpec> implicit_cumulative_or;
        implicit_cumulative_and.push_back(implicit_prerotate[0]);
        implicit_cumulative_or.push_back (implicit_prerotate[0]);
        for (unsigned int i = 1; i < implicit_prerotate.size(); i++) {
            implicit_cumulative_and.push_back(module->And(NEW_ID, implicit_prerotate[i], implicit_cumulative_and[i-1]));
            implicit_cumulative_or.push_back (module->Or(NEW_ID,  implicit_prerotate[i], implicit_cumulative_or[i-1]));
        }
        RTLIL::SigSpec implicit_rotated_reduced_sig = module->Xor(NEW_ID, implicit_cumulative_and.back(), implicit_cumulative_or.back());

        // // Option 2: rotation
        // std::vector<RTLIL::SigBit> implicit_rotated_reduced;
        // for (unsigned int i = 0; i < data_width; i++) {
        //     RTLIL::SigSpec curr_implicit_rotated;
        //     // implicit_rotated_reduced.size() here is s_size+1
        //     for (unsigned int j = 0; j < implicit_prerotate.size(); j++) {
        //         curr_implicit_rotated.append(implicit_prerotate[j][i]);
        //     }
        //     implicit_rotated_reduced.push_back(module->Ne(NEW_ID, curr_implicit_rotated, RTLIL::SigSpec(curr_implicit_rotated.extract(0, 1), curr_implicit_rotated.size())));
        // }
        // RTLIL::SigSpec implicit_rotated_reduced_sig(implicit_rotated_reduced); 


        // explicit_prereduce.size() here is s_size+1
        if (explicit_prereduce.size() != s_size+1) {
            log("explicit_prereduce.size() = %ld, s_size+1 = %d\n", explicit_prereduce.size(), s_size+1);
            log_cmd_error("explicit_prereduce.size() != s_size+1\n");
        }
        // Reduce the explicits
        std::vector<RTLIL::SigSpec> explicit_rotated_reduction_sigs;
        explicit_rotated_reduction_sigs.push_back(explicit_prereduce[0]);
        for (unsigned int i = 1; i < explicit_prereduce.size(); i++) {
            explicit_rotated_reduction_sigs.push_back(module->Or(NEW_ID, explicit_prereduce[i], explicit_rotated_reduction_sigs[i-1]));
        }
        RTLIL::SigSpec explicit_rotated_reduced_sig = explicit_rotated_reduction_sigs.back();

        module->addOr(NEW_ID, implicit_rotated_reduced_sig, explicit_rotated_reduced_sig, port_taints[Y][taint_id]);
    }
    return true;
}
