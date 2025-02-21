# rfuzz
This folder contains the yosys passes that are required to perform rfuzz instrumentation as in https://github.com/ekiwi/rfuzz.

A meaningful order of the passes could be the following:
1. mark_resets [-verbose] [-shallow]
    * Marks reset wires s.t. multiplexers controlled by these can be exluded from coverage. If the [-shallow] option is enabled, only the reset wire of the top module is considered.
2. mux_probes [-verbose] [-shallow]
    * Identifies multiplexers and wires their select signals to top if 1. they have not been marked as reset wires by the mark_resets pass and 2. no equivalent wire has not yet been wired to top. An equivalent wire is a wire that is directly connected and carries the same signal. If the [-shallow] option is enabled, it is only checked whether this exact wire with the same ID has already been wired to top.
3. port_mux_probes [-verbose]
    * The coverage signals wired to top by the mux_probes pass are concatenated to a SigSpec and set as output port. The harness generator expects the coverage port to be of this form.
4. assert_probes [-verbose]
    * $assert cells are identified and corresponding assertion signals are wired to top. The $assert cell is then deleted s.t. execution is not aborted when an assertion is violated. 
5. port_assert_probes [-verbose]
    * Analogous to the port_mux_probes pass. Assertion signals are concatenated to a SigSpec and set as output port.
6. meta_reset [-verbose]
    * Adds a meta reset logic to all registers in the design. The logic is as follows: To each FF a
    multiplexer is added. The FF input is then connected to the multiplexer input 0. The multiplexer input 1 is connected to constant 0. The meta reset wire toggles the multiplexer, synchronously setting the FF values to zero when asserted.
7. gen_toml [toml_output] [exclude_signals]
    *  Outputs the meta information about the instrumentation and DUT as requried by the harness generator. Signals can be excluding by setting exclude_signals in the form of sig1,sig2,sig3 etc. seperated by commas without whitespaces.

## cellift+rfuzz
To perform joint cellift and rfuzz instrumentation, the following pass sequence can be applied:
1. mark_resets
2. mux_probes
3. port_mux_probes
4. assert_probes
5. port_assert_probes
6. cellift
7. port_cellift_probes (analogous to other port_* passes)
8. meta_reset

This will apply cellift instrumentation to the  rfuzz-instrumented design.


