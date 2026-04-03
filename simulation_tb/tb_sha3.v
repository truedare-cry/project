//======================================================================
// tb_sha3.v - Testbench for SHA-3 RTL core (NORDUnet/Cryptech)
//
// RTL sha3.v byte-swap analysis:
//   WRITE: din_swap = {din[7:0],din[15:8],din[23:16],din[31:24]}
//          blk[lane] = din_swap  => RTL stores byte-reversed din
//   READ:  dout = {dout_swap[7:0],...,dout_swap[31:24]}
//          => RTL outputs byte-reversed state word
//
// Keccak is little-endian internally. RTL byte-swaps to interface
// with big-endian system. So testbench writes BIG-ENDIAN values:
//   0x06 domain byte in MSByte of word[0]: din = 0x06000000
//   0x80 final bit  in LSByte of last word: din = 0x00000080
//   "abc" word[0]: din = 0x61626306
//
// addr mapping: tb_addr[6:0] -> RTL port addr[8:2] (LSB-aligned)
//   tb_addr[6] -> addr[8]: 0=block, 1=state
//   tb_addr[5:1] -> addr[7:3]: 64-bit lane index
//   tb_addr[0] -> addr[2]: 0=low32, 1=high32
//======================================================================

`define SHA3_224_BLOCK_BITS  1152
`define SHA3_256_BLOCK_BITS  1088
`define SHA3_384_BLOCK_BITS   832
`define SHA3_512_BLOCK_BITS   576

`define SHA3_224_OUTPUT_BITS  224
`define SHA3_256_OUTPUT_BITS  256
`define SHA3_384_OUTPUT_BITS  384
`define SHA3_512_OUTPUT_BITS  512

module tb_sha3 ();

    //------------------------------------------------------------------
    // Known-good hash values (512-bit wide, zero-padded)
    //------------------------------------------------------------------
    localparam [511:0] SHA3_224_EMPTY_MSG = {
        224'h6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7,
        {(512-224){1'b0}} };
    localparam [511:0] SHA3_256_EMPTY_MSG = {
        256'ha7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a,
        {(512-256){1'b0}} };
    localparam [511:0] SHA3_384_EMPTY_MSG = {
        384'h0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004,
        {(512-384){1'b0}} };
    localparam [511:0] SHA3_512_EMPTY_MSG =
        512'h00a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26;

    localparam [511:0] SHA3_224_SHORT_MSG = {
        224'he642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf,
        {(512-224){1'b0}} };
    localparam [511:0] SHA3_256_SHORT_MSG = {
        256'h3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532,
        {(512-256){1'b0}} };
    localparam [511:0] SHA3_384_SHORT_MSG = {
        384'hec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25,
        {(512-384){1'b0}} };
    localparam [511:0] SHA3_512_SHORT_MSG =
        512'h00b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0;

    localparam [511:0] SHA3_224_LONG_MSG = {
        224'h9376816ABA503F72F96CE7EB65AC095DEEE3BE4BF9BBC2A1CB7E11E0,
        {(512-224){1'b0}} };
    localparam [511:0] SHA3_256_LONG_MSG = {
        256'h79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787,
        {(512-256){1'b0}} };
    localparam [511:0] SHA3_384_LONG_MSG = {
        384'h1881DE2CA7E41EF95DC4732B8F5F002B189CC1E42B74168ED1732649CE1DBCDD76197A31FD55EE989F2D7050DD473E8F,
        {(512-384){1'b0}} };
    localparam [511:0] SHA3_512_LONG_MSG =
        512'hE76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA81B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00;

    //------------------------------------------------------------------
    // Timing
    //------------------------------------------------------------------
    parameter CLK_HALF_PERIOD = 2;
    parameter CLK_PERIOD      = 2 * CLK_HALF_PERIOD;

    //------------------------------------------------------------------
    // Signals
    //------------------------------------------------------------------
    reg         tb_clk;
    reg         tb_rst_n;
    reg         tb_we;
    reg  [6:0]  tb_addr;
    reg  [31:0] tb_wr_data;
    reg         tb_dut_init;
    reg         tb_dut_next;
    wire [31:0] tb_rd_data;
    wire        tb_rdy;

    integer     i;
    integer     num_err;
    integer     block_words;
    integer     output_words;
    integer     total_bits;

    reg [511:0] hash_shreg;
    reg [31:0]  hash_word;
    reg         mismatch;

    //------------------------------------------------------------------
    // DUT instantiation
    // tb_addr[6:0] -> addr[8:2] LSB-aligned:
    //   addr[2] <- tb_addr[0]  (half select)
    //   addr[7:3] <- tb_addr[5:1] (lane index)
    //   addr[8] <- tb_addr[6]  (block/state)
    //------------------------------------------------------------------
    sha3 dut (
        .clk    (tb_clk),
        .nreset (tb_rst_n),
        .w      (tb_we),
        .addr   (tb_addr),
        .din    (tb_wr_data),
        .dout   (tb_rd_data),
        .init   (tb_dut_init),
        .next   (tb_dut_next),
        .ready  (tb_rdy)
    );

    //------------------------------------------------------------------
    // Clock
    //------------------------------------------------------------------
    initial tb_clk = 1'b0;
    always  #CLK_HALF_PERIOD tb_clk = ~tb_clk;

    //------------------------------------------------------------------
    // Task: init_sim
    //------------------------------------------------------------------
    task init_sim;
        begin
            tb_clk      = 1'b0;
            tb_rst_n    = 1'b0;
            tb_we       = 1'b0;
            tb_addr     = 7'd0;
            tb_wr_data  = 32'h0;
            tb_dut_init = 1'b0;
            tb_dut_next = 1'b0;
        end
    endtask

    //------------------------------------------------------------------
    // Task: reset_dut
    //------------------------------------------------------------------
    task reset_dut;
        begin
            $display("*** Toggling reset...");
            tb_rst_n = 1'b0;
            #(4 * CLK_HALF_PERIOD);
            tb_rst_n = 1'b1;
            #(CLK_PERIOD);
        end
    endtask

    //------------------------------------------------------------------
    // Task: write_block_word
    //
    // widx = 32-bit word index (0..49)
    // tb_addr[6]=0 (block), tb_addr[5:1]=lane=widx/2, tb_addr[0]=half=widx%2
    //
    // RTL byte-swaps din internally, so we pass big-endian values
    // (RTL converts to little-endian Keccak internally)
    //------------------------------------------------------------------
    task write_block_word;
        input integer widx;
        input [31:0]  wdata;
        begin
            tb_addr    = {1'b0, widx[5:1], widx[0]};
            tb_wr_data = wdata;
            tb_we      = 1'b1;
            #(CLK_PERIOD);
        end
    endtask

    //------------------------------------------------------------------
    // Task: sha3_sponge_pump_init
    //------------------------------------------------------------------
    task sha3_sponge_pump_init;
        reg poll_rdy;
        begin
            tb_we       = 1'b0;
            tb_dut_init = 1'b1;
            #(CLK_PERIOD);
            tb_dut_init = 1'b0;
            poll_rdy = 1'b1;
            while (poll_rdy) begin
                #(CLK_PERIOD);
                poll_rdy = (tb_rdy !== 1'b1);
            end
        end
    endtask

    //------------------------------------------------------------------
    // Task: sha3_sponge_pump_next
    //------------------------------------------------------------------
    task sha3_sponge_pump_next;
        reg poll_rdy;
        begin
            tb_we       = 1'b0;
            tb_dut_next = 1'b1;
            #(CLK_PERIOD);
            tb_dut_next = 1'b0;
            poll_rdy = 1'b1;
            while (poll_rdy) begin
                #(CLK_PERIOD);
                poll_rdy = (tb_rdy !== 1'b1);
            end
        end
    endtask

    //------------------------------------------------------------------
    // Task: compare_output
    // Read 32-bit words from state region (tb_addr[6]=1)
    // RTL dout is already byte-swapped back to big-endian
    //------------------------------------------------------------------
    task compare_output;
        input [511:0] correct_hash;
        begin
            mismatch   = 1'b0;
            hash_shreg = correct_hash;

            for (i = 0; i < output_words; i = i + 1) begin
                tb_addr = {1'b1, i[5:1], i[0]};
                tb_we   = 1'b0;
                #(CLK_PERIOD);
                hash_word = tb_rd_data;

                $display("    word[%2d]  ref=%08h  got=%08h  %s",
                    i,
                    hash_shreg[511 -: 32],
                    hash_word,
                    (hash_shreg[511 -: 32] !== hash_word) ? "*** FAIL" : "ok");

                if (hash_shreg[511 -: 32] !== hash_word) begin
                    mismatch = 1'b1;
                    num_err  = num_err + 1;
                end
                hash_shreg = {hash_shreg[479:0], {32{1'b0}}};
            end

            tb_addr = 7'd0;
            tb_we   = 1'b0;

            if (mismatch) $display("    *** FAILED\n");
            else          $display("    *** PASSED\n");
        end
    endtask

    //------------------------------------------------------------------
    // Task: test_empty_message
    //
    // SHA3 pad10*1 (big-endian interface to RTL):
    //   word[0]           = 32'h06000000  (0x06 in MSByte)
    //   word[block_words-1] = 32'h00000080  (0x80 in LSByte)
    //   others            = 32'h00000000
    //------------------------------------------------------------------
    task test_empty_message;
        input [511:0] correct_hash;
        input integer block_size;
        input integer output_size;
        begin
            $display("*** Empty msg -- %0d-bit hash, %0d-bit block",
                     output_size, block_size);

            block_words  = block_size  >> 5;
            output_words = output_size >> 5;

            #(4 * CLK_PERIOD);

            for (i = 0; i < 50; i = i + 1) begin
                if (i == 0)
                    write_block_word(i, 32'h06000000);
                else if (i == block_words - 1)
                    write_block_word(i, 32'h00000080);
                else
                    write_block_word(i, 32'h00000000);
            end

            tb_we   = 1'b0;
            tb_addr = 7'd0;
            sha3_sponge_pump_init();
            compare_output(correct_hash);
        end
    endtask

    //------------------------------------------------------------------
    // Task: test_short_message  ("abc" = 0x61 0x62 0x63)
    //
    // word[0]: bytes[31:24]=0x61, [23:16]=0x62, [15:8]=0x63, [7:0]=0x06
    //          => 32'h61626306
    //------------------------------------------------------------------
    task test_short_message;
        input [511:0] correct_hash;
        input integer block_size;
        input integer output_size;
        begin
            $display("*** Short msg (\"abc\") -- %0d-bit hash, %0d-bit block",
                     output_size, block_size);

            block_words  = block_size  >> 5;
            output_words = output_size >> 5;

            #(4 * CLK_PERIOD);

            for (i = 0; i < 50; i = i + 1) begin
                if (i == 0)
                    write_block_word(i, 32'h61626306);
                else if (i == block_words - 1)
                    write_block_word(i, 32'h00000080);
                else
                    write_block_word(i, 32'h00000000);
            end

            tb_we   = 1'b0;
            tb_addr = 7'd0;
            sha3_sponge_pump_init();
            compare_output(correct_hash);
        end
    endtask

    //------------------------------------------------------------------
    // Task: test_long_message  (200 x 0xA3 = 1600 bits)
    //------------------------------------------------------------------
    task test_long_message;
        input [511:0] correct_hash;
        input integer block_size;
        input integer output_size;

        reg done;
        reg pad_written;
        begin
            $display("*** Long msg (200x 0xA3) -- %0d-bit hash, %0d-bit block",
                     output_size, block_size);

            block_words  = block_size  >> 5;
            output_words = output_size >> 5;

            #(4 * CLK_PERIOD);

            total_bits = 1600;

            for (i = 0; i < 50; i = i + 1) begin
                if (i < block_words) begin
                    write_block_word(i, 32'hA3A3A3A3);
                    total_bits = total_bits - 32;
                end else begin
                    write_block_word(i, 32'h00000000);
                end
            end

            tb_we   = 1'b0;
            tb_addr = 7'd0;
            sha3_sponge_pump_init();

            done        = 1'b0;
            pad_written = 1'b0;

            while (!done) begin
                for (i = 0; i < block_words; i = i + 1) begin
                    if (total_bits > 0) begin
                        write_block_word(i, 32'hA3A3A3A3);
                        total_bits = total_bits - 32;
                    end else if (!pad_written) begin
                        if (i == block_words - 1) begin
                            write_block_word(i, 32'h06000080);
                            done = 1'b1;
                        end else begin
                            write_block_word(i, 32'h06000000);
                        end
                        pad_written = 1'b1;
                    end else if (i == block_words - 1) begin
                        write_block_word(i, 32'h00000080);
                        done = 1'b1;
                    end else begin
                        write_block_word(i, 32'h00000000);
                    end
                end

                tb_we   = 1'b0;
                tb_addr = 7'd0;
                sha3_sponge_pump_next();
            end

            compare_output(correct_hash);
        end
    endtask

    //------------------------------------------------------------------
    // Main stimulus
    //------------------------------------------------------------------
    initial begin : sha3_test

        $display("==============================================");
        $display("  SHA3 Testbench  --  Quartus/ModelSim");
        $display("==============================================\n");

        num_err = 0;
        init_sim();
        reset_dut();

        $display("--- Empty message ---");
        test_empty_message(SHA3_224_EMPTY_MSG, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS);
        test_empty_message(SHA3_256_EMPTY_MSG, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        test_empty_message(SHA3_384_EMPTY_MSG, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS);
        test_empty_message(SHA3_512_EMPTY_MSG, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        $display("--- Short message: \"abc\" ---");
        test_short_message(SHA3_224_SHORT_MSG, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS);
        test_short_message(SHA3_256_SHORT_MSG, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        test_short_message(SHA3_384_SHORT_MSG, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS);
        test_short_message(SHA3_512_SHORT_MSG, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        $display("--- Long message: 200 x 0xA3 ---");
        test_long_message(SHA3_224_LONG_MSG, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS);
        test_long_message(SHA3_256_LONG_MSG, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        test_long_message(SHA3_384_LONG_MSG, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS);
        test_long_message(SHA3_512_LONG_MSG, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        $display("==============================================");
        $display("  Testbench complete.");
        if (num_err == 0)
            $display("  ALL TESTS PASSED.");
        else
            $display("  %0d WORD(S) MISMATCHED.", num_err);
        $display("==============================================");

        $finish;
    end

endmodule