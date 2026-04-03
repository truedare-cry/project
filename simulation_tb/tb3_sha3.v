//======================================================================
// tb3_sha3.v — SHA3 Testbench tối ưu (Groups 1-15)
//
// KIẾN TRÚC TỐI ƯU:
//   2 task cốt lõi thay thế toàn bộ code lặp:
//
//   fill_block(msg[], n)
//     → ghi n words data + zero fill + 0x80 cuối block
//     → loop đến block_words (không phải 50)
//     → tự xóa w[] trước khi ghi → không có word dư
//
//   run_test(ref, bsz, osz)
//     → set block_words/output_words → fill_block → pump_init → check
//     → caller chỉ cần set w[]/wn trước
//
// TRƯỚC: 7 task riêng + inline loop × 6 lần = ~300 dòng lặp
// SAU:   2 task dùng chung + caller 2-3 dòng = ~60 dòng
//======================================================================

`define SHA3_224_BLOCK_BITS  1152
`define SHA3_256_BLOCK_BITS  1088
`define SHA3_384_BLOCK_BITS   832
`define SHA3_512_BLOCK_BITS   576
`define SHA3_224_OUTPUT_BITS  224
`define SHA3_256_OUTPUT_BITS  256
`define SHA3_384_OUTPUT_BITS  384
`define SHA3_512_OUTPUT_BITS  512

module tb3_sha3 ();

    // ================================================================
    // HASH REFERENCE VALUES
    // ================================================================

    // --- Group 1: Empty ---
    localparam [511:0] H224_EMPTY = { 224'h6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7, {(512-224){1'b0}} };
    localparam [511:0] H256_EMPTY = { 256'ha7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a, {(512-256){1'b0}} };
    localparam [511:0] H384_EMPTY = { 384'h0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004, {(512-384){1'b0}} };
    localparam [511:0] H512_EMPTY = 512'ha69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26;

    // --- Group 2: 0x00 ---
    localparam [511:0] H224_B00 = { 224'hbdd5167212d2dc69665f5a8875ab87f23d5ce7849132f56371a19096, {(512-224){1'b0}} };
    localparam [511:0] H256_B00 = { 256'h5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0, {(512-256){1'b0}} };
    localparam [511:0] H384_B00 = { 384'h127677f8b66725bbcb7c3eae9698351ca41e0eb6d66c784bd28dcdb3b5fb12d0c8e840342db03ad1ae180b92e3504933, {(512-384){1'b0}} };
    localparam [511:0] H512_B00 = 512'h7127aab211f82a18d06cf7578ff49d5089017944139aa60d8bee057811a15fb55a53887600a3eceba004de51105139f32506fe5b53e1913bfa6b32e716fe97da;

    // --- Group 3: 0xFF ---
    localparam [511:0] H224_BFF = { 224'h624edc8a3c0c9d42bc224f0bf37040483432d7a1aeb68935e80f1e1c, {(512-224){1'b0}} };
    localparam [511:0] H256_BFF = { 256'h444b89ecce395aec5dc98f19defd3a23bca0822fc72226f58ca46a17eeeca442, {(512-256){1'b0}} };
    localparam [511:0] H384_BFF = { 384'hbb90261c81ad316a92b5a754b983c5f09c7f22a95c34af914a46cdc50704d91279db547e47dbb00f9e2310fce0b1a028, {(512-384){1'b0}} };
    localparam [511:0] H512_BFF = 512'ha6f098adf45424539eb214272e0436894bb6fe3f22f5bf45725e1d4f37313a9547415ca108ea84664995d9ccd3983dc21806765fb8e20d6b686ce51ee6583ec8;

    // --- Group 4: 'a' ---
    localparam [511:0] H224_BA  = { 224'h9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b, {(512-224){1'b0}} };
    localparam [511:0] H256_BA  = { 256'h80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b, {(512-256){1'b0}} };
    localparam [511:0] H384_BA  = { 384'h1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9, {(512-384){1'b0}} };
    localparam [511:0] H512_BA  = 512'h697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a;

    // --- Group 5: "abc" ---
    localparam [511:0] H224_ABC = { 224'he642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf, {(512-224){1'b0}} };
    localparam [511:0] H256_ABC = { 256'h3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532, {(512-256){1'b0}} };
    localparam [511:0] H384_ABC = { 384'hec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25, {(512-384){1'b0}} };
    localparam [511:0] H512_ABC = 512'hb751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0;

    // --- Group 6: a-z ---
    localparam [511:0] H224_AZ  = { 224'h5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239, {(512-224){1'b0}} };
    localparam [511:0] H256_AZ  = { 256'h7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521, {(512-256){1'b0}} };
    localparam [511:0] H384_AZ  = { 384'hfed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f, {(512-384){1'b0}} };
    localparam [511:0] H512_AZ  = 512'haf328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68;

    // --- Group 7: Exact block boundary ---
    localparam [511:0] H256_EXB = { 256'h0adf6bfb359ae40019b67d8c49c361574b70242a6b752de6f9e0d426ca177f7a, {(512-256){1'b0}} };
    localparam [511:0] H512_EXB = 512'hd24ce75b87c7be36e3fedbaa285f563d3efcc13663f5eb2fdd0c60033dab04e894d343b3971bc0c9ba30e0dde18106cbaaa955c8c3c0bf1ec3490aafcae15788;

    // --- Group 8: 200x 0xA3 ---
    localparam [511:0] H224_A3  = { 224'h9376816ABA503F72F96CE7EB65AC095DEEE3BE4BF9BBC2A1CB7E11E0, {(512-224){1'b0}} };
    localparam [511:0] H256_A3  = { 256'h79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787, {(512-256){1'b0}} };
    localparam [511:0] H384_A3  = { 384'h1881DE2CA7E41EF95DC4732B8F5F002B189CC1E42B74168ED1732649CE1DBCDD76197A31FD55EE989F2D7050DD473E8F, {(512-384){1'b0}} };
    localparam [511:0] H512_A3  = 512'hE76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA81B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00;

    // --- Group 9: 200x 0x00 ---
    localparam [511:0] H224_Z0  = { 224'hc183b88a86c9c2d9d71f44d96983ec428d0fb59f923e337d8b339e0f, {(512-224){1'b0}} };
    localparam [511:0] H256_Z0  = { 256'h2b43036c229ba512995f91fdb46fcd5327a4dc834d86d6e0f58a08053346dc2e, {(512-256){1'b0}} };
    localparam [511:0] H384_Z0  = { 384'hd594703d816a1aeb814436c53ec54d7100c5edfb4f806a253fbf6b052864d1000b5a1a66a066b5d680bfae9ac3e5bcf6, {(512-384){1'b0}} };
    localparam [511:0] H512_Z0  = 512'hfee1198b89e041af5a26a217e4217a66c628c78d11c1fbb482b3643153f3cf0c04ae421c7e530e19584a494c1f3bd4713ca169a98b937ddf0b9d4d09fadecde9;

    // --- Group 10: "Hello, World!" (13 bytes) ---
    localparam [511:0] H224_HW  = { 224'h853048fb8b11462b6100385633c0cc8dcdc6e2b8e376c28102bc84f2, {(512-224){1'b0}} };
    localparam [511:0] H256_HW  = { 256'h1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef, {(512-256){1'b0}} };
    localparam [511:0] H384_HW  = { 384'haa9ad8a49f31d2ddcabbb7010a1566417cff803fef50eba239558826f872e468c5743e7f026b0a8e5b2d7a1cc465cdbe, {(512-384){1'b0}} };
    localparam [511:0] H512_HW  = 512'h38e05c33d7b067127f217d8c856e554fcff09c9320b8a5979ce2ff5d95dd27ba35d1fba50c562dfd1d6cc48bc9c5baa4390894418cc942d968f97bcb659419ed;

    // --- Group 11: "SHA3-256" (8 bytes) ---
    localparam [511:0] H224_S3  = { 224'hb7d63e3d0ba4ec30d9b283700de813cd11b60c189b67cb694a589d92, {(512-224){1'b0}} };
    localparam [511:0] H256_S3  = { 256'h6859382782f42da9e6169898814c6e2f9111d5e519e0eef0146cb7ba56391609, {(512-256){1'b0}} };
    localparam [511:0] H384_S3  = { 384'hc30f4895ea3b831b9ccb60cd22e044949c485ef49076c7a3ee460785849c4c18ccf262401f4f3468a60628c14527b579, {(512-384){1'b0}} };
    localparam [511:0] H512_S3  = 512'ha902116c9ce9d6c1f20229677bc9de2dec06581ad5569be8c4bf75cfe9ce4539af4f555bbe2bc154f2926b363ee60e0b090ea81d9ebda2a91b7fe3617e811700;

    // --- Group 12: "Test@2024#!" (11 bytes) ---
    localparam [511:0] H224_SP  = { 224'he0e7287fb638e01931847793541dfe21a7c4f9623b66965dae5e3870, {(512-224){1'b0}} };
    localparam [511:0] H256_SP  = { 256'h15a8d9624704640ff3610511cb62096b42560eccd918420dd5b5b08fdfc111d4, {(512-256){1'b0}} };
    localparam [511:0] H384_SP  = { 384'h74362ee50e85e500f7faaaa91961cac9564859e617a71d9e01ba098b7c2b423774669ec3bdf11a76066a50f0ccf98188, {(512-384){1'b0}} };
    localparam [511:0] H512_SP  = 512'h1da1e4091051d423520d5985886fad2ced8df512fdc9d79edfa2aee425c5b3359d58e81728f5b8985faeca97cbb4c2850128be0a7b6ad6ea6552ebe880089a48;

    // --- Group 13: A-Z uppercase (26 bytes) ---
    localparam [511:0] H224_AZU = { 224'hbeae76edd99d4ad4d398d51c5ea1d8b7b3fa6d49d687b0cb1ec2ec41, {(512-224){1'b0}} };
    localparam [511:0] H256_AZU = { 256'h738eeb2d4adf0d452456695011bb252bd4701a0ae78fdd3fc945a963bceb1702, {(512-256){1'b0}} };
    localparam [511:0] H384_AZU = { 384'h284da0df47fc9e75a4ef1248f69ca0d12a5d44508942e63b03b8c227510c2e1b43400009fcd36c0acc941679e5024a04, {(512-384){1'b0}} };
    localparam [511:0] H512_AZU = 512'h69958b041bc72e9922e02cd4250953ee69d5f6e69f97d8def72b34effc0aea2bf5cfe03bd4ada0e271060593395656c1bf9eb68d1fc4cf146f90601152222df7;

    // --- Group 14: "!@#$%^&*()" (10 bytes) ---
    localparam [511:0] H224_PC  = { 224'h20ffee9e8da8fdd7d1dc8bcded0bb585affc7d5064d7056242947054, {(512-224){1'b0}} };
    localparam [511:0] H256_PC  = { 256'h3168a455226ecc49217333a3632d13a568eae563fe057c6668e46322110a4670, {(512-256){1'b0}} };
    localparam [511:0] H384_PC  = { 384'h15fdc66ff959f7eba22bfe7abcaf316037cdaee1c227892bcd3a13a2e5d891cfc861cf6b33998bc75359bf3598569549, {(512-384){1'b0}} };
    localparam [511:0] H512_PC  = 512'hfbbcb3e21184dd4061de0b85c4756f74e36a361125733e2c7470232fc66f71c902d1e6ff7eb60cfe6b47e8b72e1429b4ff21de0fa150a2b3e8d8e29e264d56ab;

    // --- Group 15: Pangram (43 bytes) ---
    localparam [511:0] H224_PG  = { 224'hd15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795, {(512-224){1'b0}} };
    localparam [511:0] H256_PG  = { 256'h69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04, {(512-256){1'b0}} };
    localparam [511:0] H384_PG  = { 384'h7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41, {(512-384){1'b0}} };
    localparam [511:0] H512_PG  = 512'h01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450;

    // ================================================================
    // TIMING & SIGNALS
    // ================================================================
    parameter CLK_HALF_PERIOD = 2;
    // MAX_BLOCK_WORDS = SHA3-224 rate = 1152/32 = 36 words
    // RTL blk[] không tự clear → phải ghi 0 đến word 35 mỗi lần
    parameter MAX_BLOCK_WORDS = 36;
    parameter CLK_PERIOD      = 2 * CLK_HALF_PERIOD;

    reg         tb_clk;
    reg         tb_rst_n;
    reg         tb_we;
    reg  [6:0]  tb_addr;
    reg  [31:0] tb_wr_data;
    reg         tb_dut_init;
    reg         tb_dut_next;
    wire [31:0] tb_rd_data;
    wire        tb_rdy;

    integer     i, j;
    integer     num_err;
    integer     block_words;
    integer     output_words;
    integer     total_bits;

    reg [511:0] hash_shreg;
    reg [31:0]  hash_word;
    reg         mismatch;

    // Message buffer dùng chung cho tất cả groups
    reg [31:0]  w[0:15];
    integer     wn;

    // ================================================================
    // DUT
    // ================================================================
    sha3 dut (
        .clk(tb_clk), .nreset(tb_rst_n),
        .w(tb_we),    .addr(tb_addr),
        .din(tb_wr_data), .dout(tb_rd_data),
        .init(tb_dut_init), .next(tb_dut_next),
        .ready(tb_rdy)
    );

    initial tb_clk = 1'b0;
    always  #CLK_HALF_PERIOD tb_clk = ~tb_clk;

    // ================================================================
    // TASK: init_sim / reset_dut — không thay đổi
    // ================================================================
    task init_sim;
        begin
            tb_clk=0; tb_rst_n=0; tb_we=0;
            tb_addr=0; tb_wr_data=0;
            tb_dut_init=0; tb_dut_next=0;
        end
    endtask

    task reset_dut;
        begin
            $display("*** Toggling reset...");
            tb_rst_n=0; #(4*CLK_HALF_PERIOD);
            tb_rst_n=1; #(CLK_PERIOD);
        end
    endtask

    // ================================================================
    // TASK: write_word — không thay đổi (addr mapping chuẩn)
    // ================================================================
    task write_word;
        input integer idx;
        input [31:0]  data;
        begin
            tb_addr = {1'b0, idx[5:1], idx[0]};
            tb_wr_data = data;
            tb_we = 1;
            #(CLK_PERIOD);
        end
    endtask

    // ================================================================
    // TASK: pump_init / pump_next — không thay đổi
    // ================================================================
    task pump_init;
        reg p;
        begin
            tb_we=0; tb_dut_init=1; #(CLK_PERIOD); tb_dut_init=0;
            p=1; while(p) begin #(CLK_PERIOD); p=(tb_rdy!==1'b1); end
        end
    endtask

    task pump_next;
        reg p;
        begin
            tb_we=0; tb_dut_next=1; #(CLK_PERIOD); tb_dut_next=0;
            p=1; while(p) begin #(CLK_PERIOD); p=(tb_rdy!==1'b1); end
        end
    endtask

    // ================================================================
    // TASK: check — không thay đổi
    // ================================================================
    task check;
        input [511:0] ref_hash;
        begin
            mismatch=0; hash_shreg=ref_hash;
            for(i=0; i<output_words; i=i+1) begin
                tb_addr={1'b1,i[5:1],i[0]}; tb_we=0; #(CLK_PERIOD);
                hash_word=tb_rd_data;
                $display("    word[%2d]  ref=%08h  got=%08h  %s",
                    i, hash_shreg[511-:32], hash_word,
                    (hash_shreg[511-:32]!==hash_word)?"*** FAIL":"ok");
                if(hash_shreg[511-:32]!==hash_word) begin
                    mismatch=1; num_err=num_err+1; end
                hash_shreg={hash_shreg[479:0],{32{1'b0}}};
            end
            tb_addr=0; tb_we=0;
            if(mismatch) $display("    *** FAILED\n");
            else         $display("    *** PASSED\n");
        end
    endtask

    // ================================================================
    // TỐI ƯU 1: TASK fill_block
    // Ghi w[0..wn-1] vào block RAM, zero fill, 0x80 cuối block
    //
    // Cải tiến so với trước:
    //   - Loop đến block_words (không phải 50 hardcode)
    //     → SHA3-512 block = 18 words: tiết kiệm 32 write calls
    //   - Xóa w[j] = 0 sau khi ghi (auto-clear)
    //     → không còn word dư từ test trước
    //   - Một task duy nhất cho tất cả 15 groups
    //     → thay thế test_empty, test_1byte, test_abc, test_az_lower,
    //        và 6 inline loop của G10-G15
    // ================================================================
    task fill_block;
        // QUAN TRỌNG: loop đến MAX_BLOCK_WORDS (36), KHÔNG phải block_words
        // RTL blk[0:24] không tự clear giữa các test
        // SHA3-224 dùng 36 words (lanes 0-17), SHA3-256 dùng 34 words
        // Nếu chỉ ghi đến 34 words, lane 17 còn giá trị từ test SHA3-224 trước đó
        // → RTL absorb dữ liệu sai → hash sai cho tất cả 256/384/512
        begin
            #(4*CLK_PERIOD);
            for(i=0; i<MAX_BLOCK_WORDS; i=i+1) begin
                if(i < wn)
                    write_word(i, w[i]);          // data words
                else if(i == block_words-1)
                    write_word(i, 32'h00000080);  // final bit ở word cuối của variant này
                else
                    write_word(i, 32'h00000000);  // zero fill (xóa cả vùng ngoài rate)
            end
            // Auto-clear w[] sau khi ghi
            for(j=0; j<16; j=j+1) w[j] = 32'h0;
            tb_we=0; tb_addr=0;
        end
    endtask

    // ================================================================
    // TỐI ƯU 2: TASK run_test
    // Set block/output words → fill_block → pump_init → check
    //
    // Cải tiến so với trước:
    //   - Caller chỉ cần: set w[], wn → run_test(ref, bsz, osz)
    //   - 2 dòng caller thay vì ~15 dòng inline loop
    //   - Tất cả 4 variants (224/256/384/512) gọi cùng 1 task
    // ================================================================
    task run_test;
        input [511:0] ref;
        input integer bsz, osz;
        begin
            block_words  = bsz >> 5;  // block_bits / 32
            output_words = osz >> 5;  // output_bits / 32
            fill_block();
            pump_init();
            check(ref);
        end
    endtask

    // ================================================================
    // TỐI ƯU 3: TASK run_test_next
    // Cho exact block boundary: fill block 2 rồi pump_next
    // Caller đã gọi pump_init cho block 1 trước đó
    // ================================================================
    task run_test_next;
        input [511:0] ref;
        input integer bsz, osz;
        begin
            block_words  = bsz >> 5;
            output_words = osz >> 5;
            fill_block();
            pump_next();
            check(ref);
        end
    endtask

    // ================================================================
    // TỐI ƯU 4: TASK test_long_byte — giữ lại vì multi-block phức tạp
    // Nhưng tối ưu loop đến block_words thay vì 50
    // ================================================================
    task test_long_byte;
        input [511:0] ref;
        input integer bsz, osz;
        input [7:0]   val;
        reg [31:0] fill;
        reg        done, padded;
        begin
            $display("*** Long 200x 0x%02h -- %0d-bit", val, osz);
            fill         = {val, val, val, val};
            block_words  = bsz >> 5;
            output_words = osz >> 5;
            #(4*CLK_PERIOD);

            // Block 1 (init): fill data đến block_words, zero phần ngoài đến MAX_BLOCK_WORDS
            total_bits = 1600;
            for(i=0; i<MAX_BLOCK_WORDS; i=i+1) begin
                if(i < block_words) begin
                    write_word(i, fill);
                    total_bits = total_bits - 32;
                end else
                    write_word(i, 32'h00000000);  // clear vùng ngoài rate
            end
            tb_we=0; tb_addr=0;
            pump_init();

            // Các block tiếp theo (next): data → padding → clear vùng ngoài rate
            done=0; padded=0;
            while(!done) begin
                for(i=0; i<MAX_BLOCK_WORDS; i=i+1) begin
                    if(i >= block_words)
                        write_word(i, 32'h00000000);  // clear vùng ngoài rate
                    else if(total_bits > 0) begin
                        write_word(i, fill);
                        total_bits = total_bits - 32;
                    end else if(!padded) begin
                        if(i == block_words-1) begin
                            write_word(i, 32'h06000080); done=1;
                        end else
                            write_word(i, 32'h06000000);
                        padded = 1;
                    end else if(i == block_words-1) begin
                        write_word(i, 32'h00000080); done=1;
                    end else
                        write_word(i, 32'h00000000);
                end
                tb_we=0; tb_addr=0;
                pump_next();
            end
            check(ref);
        end
    endtask

    // ================================================================
    // MAIN STIMULUS
    // Mỗi test chỉ cần: set w[], wn → run_test(ref, bsz, osz)
    // ================================================================
    initial begin : sha3_test

        $display("==============================================");
        $display("  SHA3 Testbench Optimised (Groups 1-15)");
        $display("==============================================\n");
        num_err=0; init_sim(); reset_dut();

        // ---- G1: Empty message ----
        // w[] trống (wn=0), fill_block chỉ ghi 0x06 + zeros + 0x80
        // Khác biệt: không cần hardcode word[0]=0x06000000 nữa
        // vì w[0] = 0x00 và task tự detect wn=0
        // → NHƯNG empty cần 0x06 ở word[0], nên set wn=1
        $display("=== G1: Empty message ===");
        w[0]=32'h06000000; wn=1;
        run_test(H224_EMPTY, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS);
        w[0]=32'h06000000; wn=1;
        run_test(H256_EMPTY, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        w[0]=32'h06000000; wn=1;
        run_test(H384_EMPTY, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS);
        w[0]=32'h06000000; wn=1;
        run_test(H512_EMPTY, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G2: Single byte 0x00 ----
        // word[0] = {0x00, 0x06, 0x00, 0x00}
        $display("=== G2: Single byte 0x00 ===");
        $display("*** 1 byte 0x00");
        w[0]=32'h00060000; wn=1;
        run_test(H224_B00, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS);
        w[0]=32'h00060000; wn=1;
        run_test(H256_B00, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        w[0]=32'h00060000; wn=1;
        run_test(H384_B00, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS);
        w[0]=32'h00060000; wn=1;
        run_test(H512_B00, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G3: Single byte 0xFF ----
        $display("=== G3: Single byte 0xFF ===");
        $display("*** 1 byte 0xFF");
        w[0]=32'hFF060000; wn=1;
        run_test(H224_BFF, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS);
        w[0]=32'hFF060000; wn=1;
        run_test(H256_BFF, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        w[0]=32'hFF060000; wn=1;
        run_test(H384_BFF, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS);
        w[0]=32'hFF060000; wn=1;
        run_test(H512_BFF, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G4: Single byte 'a' ----
        $display("=== G4: Single byte 'a' ===");
        $display("*** 1 byte 0x61");
        w[0]=32'h61060000; wn=1;
        run_test(H224_BA, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS);
        w[0]=32'h61060000; wn=1;
        run_test(H256_BA, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        w[0]=32'h61060000; wn=1;
        run_test(H384_BA, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS);
        w[0]=32'h61060000; wn=1;
        run_test(H512_BA, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G5: "abc" ----
        // word[0] = {0x61, 0x62, 0x63, 0x06}
        $display("=== G5: abc ===");
        $display("*** abc");
        w[0]=32'h61626306; wn=1;
        run_test(H224_ABC, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS);
        w[0]=32'h61626306; wn=1;
        run_test(H256_ABC, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        w[0]=32'h61626306; wn=1;
        run_test(H384_ABC, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS);
        w[0]=32'h61626306; wn=1;
        run_test(H512_ABC, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G6: a-z lowercase (26 bytes) ----
        $display("=== G6: a-z lowercase ===");
        $display("*** a-z (26B)");
        w[0]=32'h61626364; w[1]=32'h65666768; w[2]=32'h696a6b6c;
        w[3]=32'h6d6e6f70; w[4]=32'h71727374; w[5]=32'h75767778;
        w[6]=32'h797a0600; wn=7;
        run_test(H224_AZ, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS);
        w[0]=32'h61626364; w[1]=32'h65666768; w[2]=32'h696a6b6c;
        w[3]=32'h6d6e6f70; w[4]=32'h71727374; w[5]=32'h75767778;
        w[6]=32'h797a0600; wn=7;
        run_test(H256_AZ, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        w[0]=32'h61626364; w[1]=32'h65666768; w[2]=32'h696a6b6c;
        w[3]=32'h6d6e6f70; w[4]=32'h71727374; w[5]=32'h75767778;
        w[6]=32'h797a0600; wn=7;
        run_test(H384_AZ, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS);
        w[0]=32'h61626364; w[1]=32'h65666768; w[2]=32'h696a6b6c;
        w[3]=32'h6d6e6f70; w[4]=32'h71727374; w[5]=32'h75767778;
        w[6]=32'h797a0600; wn=7;
        run_test(H512_AZ, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G7: Exact block boundary ----
        // Block 1: fill A3A3A3A3 × block_words → pump_init
        // Block 2: 0x06 + zeros + 0x80 → pump_next
        $display("=== G7: Exact block boundary ===");
        // SHA3-256: 136 bytes = 34 words
        $display("*** Exact block (0xA3 x 136B) -- 256-bit");
        block_words=`SHA3_256_BLOCK_BITS>>5; output_words=`SHA3_256_OUTPUT_BITS>>5;
        #(4*CLK_PERIOD);
        for(i=0; i<MAX_BLOCK_WORDS; i=i+1)
            write_word(i, (i<block_words) ? 32'hA3A3A3A3 : 32'h00000000);
        tb_we=0; tb_addr=0; pump_init();
        w[0]=32'h06000000; wn=1;
        run_test_next(H256_EXB, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        // SHA3-512: 72 bytes = 18 words
        $display("*** Exact block (0xA3 x 72B) -- 512-bit");
        block_words=`SHA3_512_BLOCK_BITS>>5; output_words=`SHA3_512_OUTPUT_BITS>>5;
        #(4*CLK_PERIOD);
        for(i=0; i<MAX_BLOCK_WORDS; i=i+1)
            write_word(i, (i<block_words) ? 32'hA3A3A3A3 : 32'h00000000);
        tb_we=0; tb_addr=0; pump_init();
        w[0]=32'h06000000; wn=1;
        run_test_next(H512_EXB, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G8: 200x 0xA3 ----
        $display("=== G8: Long 200x 0xA3 ===");
        test_long_byte(H224_A3, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS, 8'hA3);
        test_long_byte(H256_A3, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS, 8'hA3);
        test_long_byte(H384_A3, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS, 8'hA3);
        test_long_byte(H512_A3, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS, 8'hA3);

        // ---- G9: 200x 0x00 ----
        $display("=== G9: Long 200x 0x00 ===");
        test_long_byte(H224_Z0, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS, 8'h00);
        test_long_byte(H256_Z0, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS, 8'h00);
        test_long_byte(H384_Z0, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS, 8'h00);
        test_long_byte(H512_Z0, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS, 8'h00);

        // ---- G10: "Hello, World!" (13 bytes) ----
        // Caller: set w[], wn → run_test 4 lần
        // 2 dòng setup + 4 × run_test thay vì 4 × 15 dòng inline
        $display("=== G10: Hello, World! ===");
        $display("*** Hello World -- 224-bit");
        w[0]=32'h48656C6C; w[1]=32'h6F2C2057;
        w[2]=32'h6F726C64; w[3]=32'h21060000; wn=4;
        run_test(H224_HW, `SHA3_224_BLOCK_BITS, `SHA3_224_OUTPUT_BITS);
        $display("*** Hello World -- 256-bit");
        w[0]=32'h48656C6C; w[1]=32'h6F2C2057;
        w[2]=32'h6F726C64; w[3]=32'h21060000; wn=4;
        run_test(H256_HW, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        $display("*** Hello World -- 384-bit");
        w[0]=32'h48656C6C; w[1]=32'h6F2C2057;
        w[2]=32'h6F726C64; w[3]=32'h21060000; wn=4;
        run_test(H384_HW, `SHA3_384_BLOCK_BITS, `SHA3_384_OUTPUT_BITS);
        $display("*** Hello World -- 512-bit");
        w[0]=32'h48656C6C; w[1]=32'h6F2C2057;
        w[2]=32'h6F726C64; w[3]=32'h21060000; wn=4;
        run_test(H512_HW, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G11: "SHA3-256" (8 bytes, len%4==0) ----
        $display("=== G11: SHA3-256 str ===");
        $display("*** SHA3-256 str -- 256-bit");
        w[0]=32'h53484133; w[1]=32'h2D323536; w[2]=32'h06000000; wn=3;
        run_test(H256_S3, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        $display("*** SHA3-256 str -- 512-bit");
        w[0]=32'h53484133; w[1]=32'h2D323536; w[2]=32'h06000000; wn=3;
        run_test(H512_S3, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G12: "Test@2024#!" (11 bytes) ----
        $display("=== G12: Test@2024#! ===");
        $display("*** Test@2024#! -- 256-bit");
        w[0]=32'h54657374; w[1]=32'h40323032; w[2]=32'h34232106; wn=3;
        run_test(H256_SP, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        $display("*** Test@2024#! -- 512-bit");
        w[0]=32'h54657374; w[1]=32'h40323032; w[2]=32'h34232106; wn=3;
        run_test(H512_SP, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G13: A-Z uppercase (26 bytes) ----
        $display("=== G13: A-Z uppercase ===");
        $display("*** A-Z -- 256-bit");
        w[0]=32'h41424344; w[1]=32'h45464748; w[2]=32'h494A4B4C;
        w[3]=32'h4D4E4F50; w[4]=32'h51525354; w[5]=32'h55565758;
        w[6]=32'h595A0600; wn=7;
        run_test(H256_AZU, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        $display("*** A-Z -- 512-bit");
        w[0]=32'h41424344; w[1]=32'h45464748; w[2]=32'h494A4B4C;
        w[3]=32'h4D4E4F50; w[4]=32'h51525354; w[5]=32'h55565758;
        w[6]=32'h595A0600; wn=7;
        run_test(H512_AZU, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G14: "!@#$%^&*()" (10 bytes) ----
        $display("=== G14: !@#$%%^&*() ===");
        $display("*** !@#$%%^&*() -- 256-bit");
        w[0]=32'h21402324; w[1]=32'h255E262A; w[2]=32'h28290600; wn=3;
        run_test(H256_PC, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        $display("*** !@#$%%^&*() -- 512-bit");
        w[0]=32'h21402324; w[1]=32'h255E262A; w[2]=32'h28290600; wn=3;
        run_test(H512_PC, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ---- G15: Pangram (43 bytes) ----
        $display("=== G15: Pangram (43B) ===");
        $display("*** Pangram -- 256-bit");
        w[ 0]=32'h54686520; w[ 1]=32'h71756963; w[ 2]=32'h6B206272;
        w[ 3]=32'h6F776E20; w[ 4]=32'h666F7820; w[ 5]=32'h6A756D70;
        w[ 6]=32'h73206F76; w[ 7]=32'h65722074; w[ 8]=32'h6865206C;
        w[ 9]=32'h617A7920; w[10]=32'h646F6706; wn=11;
        run_test(H256_PG, `SHA3_256_BLOCK_BITS, `SHA3_256_OUTPUT_BITS);
        $display("*** Pangram -- 512-bit");
        w[ 0]=32'h54686520; w[ 1]=32'h71756963; w[ 2]=32'h6B206272;
        w[ 3]=32'h6F776E20; w[ 4]=32'h666F7820; w[ 5]=32'h6A756D70;
        w[ 6]=32'h73206F76; w[ 7]=32'h65722074; w[ 8]=32'h6865206C;
        w[ 9]=32'h617A7920; w[10]=32'h646F6706; wn=11;
        run_test(H512_PG, `SHA3_512_BLOCK_BITS, `SHA3_512_OUTPUT_BITS);

        // ================================================================
        $display("==============================================");
        $display("  Testbench complete. %0d groups tested.", 15);
        if(num_err==0) $display("  ALL TESTS PASSED.");
        else           $display("  %0d WORD(S) MISMATCHED.", num_err);
        $display("==============================================");
        $finish;
    end

endmodule