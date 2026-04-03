//======================================================================
// tb4_sha3.v — SHA3 Testbench dùng sha3_bank (Groups 1-15)
//
// KIẾN TRÚC THỬ:
//   ┌─────────────┐     gen_load()      ┌──────────────┐
//   │  sha3_bank  │ ─────────────────▶  │  gen_words[] │
//   │   (gen)     │   set_variant()     │  gen_block_  │
//   └─────────────┘                     │  words/total │
//          │                            └──────┬───────┘
//          │ fill_from_gen()                   │
//          ▼                                   ▼
//   ┌─────────────┐   write_word()    ┌──────────────┐
//   │  tb4_sha3   │ ────────────────▶ │  sha3 (DUT)  │
//   │ (this file) │   pump_init/next  │  blk[] → st[]│
//   └─────────────┘   check()         └──────────────┘
//
// QUY TẮC QUAN TRỌNG:
//   set_variant() PHẢI gọi TRƯỚC gen_load()
//   Lý do: gen_load() → do_pad() dùng blk_bytes
//           blk_bytes chỉ được set khi gọi set_variant()
//           Nếu gọi sai thứ tự → blk_bytes=0 → padding sai → hash sai
//
// THÊM TEST CASE MỚI (chỉ 3 bước):
//   1. Thêm `define STR_XXX + case vào sha3_bank.v
//   2. Tính hash ref bằng sha3_gen_tb.py
//   3. Thêm 3 dòng: set_variant → gen.gen_load → run_from_gen
//======================================================================

// Include sha3_bank.v — chứa toàn bộ logic sinh word + padding
// sha3_bank cung cấp: gen_load(), set_variant(), gen_block_word(), ...
`include "sha3_bank.v"

// Kích thước block (bit) theo từng SHA3 variant
// SHA3-224: rate = 1600 - 2×224 = 1152 bit = 144 byte = 36 word
// SHA3-256: rate = 1600 - 2×256 = 1088 bit = 136 byte = 34 word
// SHA3-384: rate = 1600 - 2×384 =  832 bit = 104 byte = 26 word
// SHA3-512: rate = 1600 - 2×512 =  576 bit =  72 byte = 18 word
`define SHA3_224_BLOCK_BITS  1152
`define SHA3_256_BLOCK_BITS  1088
`define SHA3_384_BLOCK_BITS   832
`define SHA3_512_BLOCK_BITS   576

// Số bit output của từng variant (= kích thước hash digest)
`define SHA3_224_OUTPUT_BITS  224
`define SHA3_256_OUTPUT_BITS  256
`define SHA3_384_OUTPUT_BITS  384
`define SHA3_512_OUTPUT_BITS  512

module tb4_sha3 ();

    // ================================================================
    // HASH REFERENCE VALUES
    // Các giá trị hash chuẩn (golden values) dùng để so sánh kết quả
    // Nguồn: NIST FIPS 202 test vectors
    //
    // Định dạng: [511:0] — luôn dùng 512-bit để thống nhất
    //   SHA3-224: 224-bit hash + 288-bit zero padding
    //   SHA3-256: 256-bit hash + 256-bit zero padding
    //   SHA3-384: 384-bit hash + 128-bit zero padding
    //   SHA3-512: 512-bit hash (không cần padding)
    // ================================================================

    // --- Group 1: Empty message (0 byte) ---
    // SHA3("") — hash của chuỗi rỗng
    localparam [511:0] H224_EMPTY = { 224'h6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7, {(512-224){1'b0}} };
    localparam [511:0] H256_EMPTY = { 256'ha7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a, {(512-256){1'b0}} };
    localparam [511:0] H384_EMPTY = { 384'h0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004, {(512-384){1'b0}} };
    localparam [511:0] H512_EMPTY = 512'ha69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26;

    // --- Group 2: Single byte 0x00 ---
    // SHA3(0x00) — kiểm tra byte giá trị 0 (không phải chuỗi rỗng)
    localparam [511:0] H224_B00 = { 224'hbdd5167212d2dc69665f5a8875ab87f23d5ce7849132f56371a19096, {(512-224){1'b0}} };
    localparam [511:0] H256_B00 = { 256'h5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0, {(512-256){1'b0}} };
    localparam [511:0] H384_B00 = { 384'h127677f8b66725bbcb7c3eae9698351ca41e0eb6d66c784bd28dcdb3b5fb12d0c8e840342db03ad1ae180b92e3504933, {(512-384){1'b0}} };
    localparam [511:0] H512_B00 = 512'h7127aab211f82a18d06cf7578ff49d5089017944139aa60d8bee057811a15fb55a53887600a3eceba004de51105139f32506fe5b53e1913bfa6b32e716fe97da;

    // --- Group 3: Single byte 0xFF ---
    // SHA3(0xFF) — kiểm tra byte all-ones, dễ gây lỗi borrow/carry
    localparam [511:0] H224_BFF = { 224'h624edc8a3c0c9d42bc224f0bf37040483432d7a1aeb68935e80f1e1c, {(512-224){1'b0}} };
    localparam [511:0] H256_BFF = { 256'h444b89ecce395aec5dc98f19defd3a23bca0822fc72226f58ca46a17eeeca442, {(512-256){1'b0}} };
    localparam [511:0] H384_BFF = { 384'hbb90261c81ad316a92b5a754b983c5f09c7f22a95c34af914a46cdc50704d91279db547e47dbb00f9e2310fce0b1a028, {(512-384){1'b0}} };
    localparam [511:0] H512_BFF = 512'ha6f098adf45424539eb214272e0436894bb6fe3f22f5bf45725e1d4f37313a9547415ca108ea84664995d9ccd3983dc21806765fb8e20d6b686ce51ee6583ec8;

    // --- Group 4: Single byte 'a' (0x61) ---
    // SHA3("a") — ký tự ASCII đơn giản
    localparam [511:0] H224_BA  = { 224'h9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b, {(512-224){1'b0}} };
    localparam [511:0] H256_BA  = { 256'h80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b, {(512-256){1'b0}} };
    localparam [511:0] H384_BA  = { 384'h1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9, {(512-384){1'b0}} };
    localparam [511:0] H512_BA  = 512'h697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a;

    // --- Group 5: "abc" (3 bytes) ---
    // SHA3("abc") — vector chuẩn NIST, kiểm tra cơ bản nhất
    localparam [511:0] H224_ABC = { 224'he642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf, {(512-224){1'b0}} };
    localparam [511:0] H256_ABC = { 256'h3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532, {(512-256){1'b0}} };
    localparam [511:0] H384_ABC = { 384'hec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25, {(512-384){1'b0}} };
    localparam [511:0] H512_ABC = 512'hb751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0;

    // --- Group 6: "abcdefghijklmnopqrstuvwxyz" (26 bytes) ---
    // SHA3(a-z) — kiểm tra chuỗi dài hơn, nhiều word hơn
    localparam [511:0] H224_AZ  = { 224'h5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239, {(512-224){1'b0}} };
    localparam [511:0] H256_AZ  = { 256'h7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521, {(512-256){1'b0}} };
    localparam [511:0] H384_AZ  = { 384'hfed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f, {(512-384){1'b0}} };
    localparam [511:0] H512_AZ  = 512'haf328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68;

    // --- Group 7: Exact block boundary ---
    // SHA3(0xA3 × rate_bytes) — message khớp chính xác 1 block
    // Đây là edge case: toàn bộ rate byte là data, padding phải sang block 2
    // Chỉ test 256 và 512 vì block size khác nhau
    localparam [511:0] H256_EXB = { 256'h0adf6bfb359ae40019b67d8c49c361574b70242a6b752de6f9e0d426ca177f7a, {(512-256){1'b0}} };
    localparam [511:0] H512_EXB = 512'hd24ce75b87c7be36e3fedbaa285f563d3efcc13663f5eb2fdd0c60033dab04e894d343b3971bc0c9ba30e0dde18106cbaaa955c8c3c0bf1ec3490aafcae15788;

    // --- Group 8: 200 bytes of 0xA3 (multi-block) ---
    // SHA3(0xA3 × 200) — NIST official long test vector
    // 200 byte > 1 block với mọi variant → bắt buộc phải dùng pump_next
    localparam [511:0] H224_A3  = { 224'h9376816ABA503F72F96CE7EB65AC095DEEE3BE4BF9BBC2A1CB7E11E0, {(512-224){1'b0}} };
    localparam [511:0] H256_A3  = { 256'h79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787, {(512-256){1'b0}} };
    localparam [511:0] H384_A3  = { 384'h1881DE2CA7E41EF95DC4732B8F5F002B189CC1E42B74168ED1732649CE1DBCDD76197A31FD55EE989F2D7050DD473E8F, {(512-384){1'b0}} };
    localparam [511:0] H512_A3  = 512'hE76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA81B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00;

    // --- Group 9: 200 bytes of 0x00 (multi-block, all-zero) ---
    // SHA3(0x00 × 200) — giống G8 nhưng toàn byte 0
    // Kiểm tra trường hợp data và padding trùng giá trị (đều là 0)
    localparam [511:0] H224_Z0  = { 224'hc183b88a86c9c2d9d71f44d96983ec428d0fb59f923e337d8b339e0f, {(512-224){1'b0}} };
    localparam [511:0] H256_Z0  = { 256'h2b43036c229ba512995f91fdb46fcd5327a4dc834d86d6e0f58a08053346dc2e, {(512-256){1'b0}} };
    localparam [511:0] H384_Z0  = { 384'hd594703d816a1aeb814436c53ec54d7100c5edfb4f806a253fbf6b052864d1000b5a1a66a066b5d680bfae9ac3e5bcf6, {(512-384){1'b0}} };
    localparam [511:0] H512_Z0  = 512'hfee1198b89e041af5a26a217e4217a66c628c78d11c1fbb482b3643153f3cf0c04ae421c7e530e19584a494c1f3bd4713ca169a98b937ddf0b9d4d09fadecde9;

    // --- Group 10: "Hello, World!" (13 bytes) ---
    // Chuỗi thực tế có chữ hoa, thường, dấu câu và khoảng trắng
    localparam [511:0] H224_HW  = { 224'h853048fb8b11462b6100385633c0cc8dcdc6e2b8e376c28102bc84f2, {(512-224){1'b0}} };
    localparam [511:0] H256_HW  = { 256'h1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef, {(512-256){1'b0}} };
    localparam [511:0] H384_HW  = { 384'haa9ad8a49f31d2ddcabbb7010a1566417cff803fef50eba239558826f872e468c5743e7f026b0a8e5b2d7a1cc465cdbe, {(512-384){1'b0}} };
    localparam [511:0] H512_HW  = 512'h38e05c33d7b067127f217d8c856e554fcff09c9320b8a5979ce2ff5d95dd27ba35d1fba50c562dfd1d6cc48bc9c5baa4390894418cc942d968f97bcb659419ed;

    // --- Group 11: "SHA3-256" (8 bytes) ---
    // Chuỗi chữ hoa + hyphen + số — kiểm tra ký tự đặc biệt ASCII in được
    localparam [511:0] H224_S3  = { 224'hb7d63e3d0ba4ec30d9b283700de813cd11b60c189b67cb694a589d92, {(512-224){1'b0}} };
    localparam [511:0] H256_S3  = { 256'h6859382782f42da9e6169898814c6e2f9111d5e519e0eef0146cb7ba56391609, {(512-256){1'b0}} };
    localparam [511:0] H384_S3  = { 384'hc30f4895ea3b831b9ccb60cd22e044949c485ef49076c7a3ee460785849c4c18ccf262401f4f3468a60628c14527b579, {(512-384){1'b0}} };
    localparam [511:0] H512_S3  = 512'ha902116c9ce9d6c1f20229677bc9de2dec06581ad5569be8c4bf75cfe9ce4539af4f555bbe2bc154f2926b363ee60e0b090ea81d9ebda2a91b7fe3617e811700;

    // --- Group 12: "Test@2024#!" (11 bytes) ---
    // Mix chữ hoa/thường + số + ký tự đặc biệt — kiểm tra mật khẩu thực tế
    localparam [511:0] H224_SP  = { 224'he0e7287fb638e01931847793541dfe21a7c4f9623b66965dae5e3870, {(512-224){1'b0}} };
    localparam [511:0] H256_SP  = { 256'h15a8d9624704640ff3610511cb62096b42560eccd918420dd5b5b08fdfc111d4, {(512-256){1'b0}} };
    localparam [511:0] H384_SP  = { 384'h74362ee50e85e500f7faaaa91961cac9564859e617a71d9e01ba098b7c2b423774669ec3bdf11a76066a50f0ccf98188, {(512-384){1'b0}} };
    localparam [511:0] H512_SP  = 512'h1da1e4091051d423520d5985886fad2ced8df512fdc9d79edfa2aee425c5b3359d58e81728f5b8985faeca97cbb4c2850128be0a7b6ad6ea6552ebe880089a48;

    // --- Group 13: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" (26 bytes) ---
    // Đối xứng với G6 — kiểm tra phân biệt chữ hoa/thường
    localparam [511:0] H224_AZU = { 224'hbeae76edd99d4ad4d398d51c5ea1d8b7b3fa6d49d687b0cb1ec2ec41, {(512-224){1'b0}} };
    localparam [511:0] H256_AZU = { 256'h738eeb2d4adf0d452456695011bb252bd4701a0ae78fdd3fc945a963bceb1702, {(512-256){1'b0}} };
    localparam [511:0] H384_AZU = { 384'h284da0df47fc9e75a4ef1248f69ca0d12a5d44508942e63b03b8c227510c2e1b43400009fcd36c0acc941679e5024a04, {(512-384){1'b0}} };
    localparam [511:0] H512_AZU = 512'h69958b041bc72e9922e02cd4250953ee69d5f6e69f97d8def72b34effc0aea2bf5cfe03bd4ada0e271060593395656c1bf9eb68d1fc4cf146f90601152222df7;

    // --- Group 14: "!@#$%^&*()" (10 bytes) ---
    // Ký tự đặc biệt thuần túy — kiểm tra các byte ASCII ngoài alphanumeric
    localparam [511:0] H224_PC  = { 224'h20ffee9e8da8fdd7d1dc8bcded0bb585affc7d5064d7056242947054, {(512-224){1'b0}} };
    localparam [511:0] H256_PC  = { 256'h3168a455226ecc49217333a3632d13a568eae563fe057c6668e46322110a4670, {(512-256){1'b0}} };
    localparam [511:0] H384_PC  = { 384'h15fdc66ff959f7eba22bfe7abcaf316037cdaee1c227892bcd3a13a2e5d891cfc861cf6b33998bc75359bf3598569549, {(512-384){1'b0}} };
    localparam [511:0] H512_PC  = 512'hfbbcb3e21184dd4061de0b85c4756f74e36a361125733e2c7470232fc66f71c902d1e6ff7eb60cfe6b47e8b72e1429b4ff21de0fa150a2b3e8d8e29e264d56ab;

    // --- Group 15: Pangram (43 bytes) ---
    // "The quick brown fox jumps over the lazy dog" — dùng đủ 26 chữ cái
    localparam [511:0] H224_PG  = { 224'hd15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795, {(512-224){1'b0}} };
    localparam [511:0] H256_PG  = { 256'h69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04, {(512-256){1'b0}} };
    localparam [511:0] H384_PG  = { 384'h7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41, {(512-384){1'b0}} };
    localparam [511:0] H512_PG  = 512'h01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450;


    // ================================================================
    // TIMING & SIGNALS
    // CLK_HALF_PERIOD=2 → CLK_PERIOD=4ns → f=250MHz (sim, không cần thực)
    // MAX_BLOCK_WORDS=36 = SHA3-224 block size (lớn nhất trong 4 variant)
    //   Luôn ghi đủ 36 word mỗi block để xóa sạch vùng blk[] cũ trong RTL
    //   (RTL không tự clear blk[] giữa các test)
    // ================================================================
    parameter CLK_HALF_PERIOD = 2;
    parameter CLK_PERIOD      = 2 * CLK_HALF_PERIOD;
    parameter MAX_BLOCK_WORDS = 36;  // SHA3-224 rate = 36 words = max mọi variant

    // Bus tín hiệu kết nối testbench với DUT
    reg         tb_clk;
    reg         tb_rst_n;       // Reset tích cực thấp
    reg         tb_we;          // Write enable: 1=ghi vào blk[]
    reg  [6:0]  tb_addr;        // Địa chỉ word: {1'b0, idx[5:1], idx[0]}
    reg  [31:0] tb_wr_data;     // Data ghi vào
    reg         tb_dut_init;    // 1 xung: bắt đầu block đầu (absorb init)
    reg         tb_dut_next;    // 1 xung: block tiếp theo (absorb next)
    wire [31:0] tb_rd_data;     // Data đọc ra từ state
    wire        tb_rdy;         // 1=DUT rảnh, 0=đang tính 24 vòng Keccak

    // Biến phụ trợ của testbench
    integer     i;
    integer     num_err;        // Tổng số word mismatch (0 = all pass)
    integer     block_words;    // Số word/block của variant hiện tại
    integer     output_words;   // Số word output cần đọc để check

    // Thanh ghi hỗ trợ task check()
    reg [511:0] hash_shreg;     // Shift register chứa giá trị ref đang check
    reg [31:0]  hash_word;      // Word vừa đọc từ DUT
    reg         mismatch;       // Cờ: 1 nếu có ít nhất 1 word sai trong test hiện tại


    // ================================================================
    // KHỞI TẠO DUT VÀ GENERATOR
    // sha3: DUT cần verify
    // sha3_bank gen(): instance generator — cung cấp word + padding
    // ================================================================

    // DUT: SHA3 core RTL cần kiểm tra
    sha3 dut (
        .clk(tb_clk), .nreset(tb_rst_n),
        .w(tb_we),    .addr(tb_addr),
        .din(tb_wr_data), .dout(tb_rd_data),
        .init(tb_dut_init), .next(tb_dut_next),
        .ready(tb_rdy)
    );

    // Generator: cung cấp word đã pad sẵn → tb không cần tính tay
    sha3_bank gen();

    // Clock: toggle mỗi CLK_HALF_PERIOD
    initial tb_clk = 1'b0;
    always  #CLK_HALF_PERIOD tb_clk = ~tb_clk;


    // ================================================================
    // TASK: init_sim
    // Đặt tất cả tín hiệu về trạng thái mặc định an toàn trước khi bắt đầu
    // Gọi 1 lần duy nhất ở đầu initial block
    // ================================================================
    task init_sim;
        begin
            tb_clk=0; tb_rst_n=0; tb_we=0;
            tb_addr=0; tb_wr_data=0;
            tb_dut_init=0; tb_dut_next=0;
        end
    endtask

    // ================================================================
    // TASK: reset_dut
    // Toggle reset để DUT về trạng thái khởi tạo:
    //   - st[] và blk[] cleared về 0
    //   - round = SHA3_NUM_ROUNDS (24) = idle
    //   - ready = 1
    // ================================================================
    task reset_dut;
        begin
            $display("*** Toggling reset...");
            tb_rst_n=0; #(4*CLK_HALF_PERIOD);   // Giữ reset ít nhất 2 clock
            tb_rst_n=1; #(CLK_PERIOD);           // Chờ 1 clock để ổn định
        end
    endtask

    // ================================================================
    // TASK: write_word
    // Ghi 1 word 32-bit vào block buffer của DUT (blk[])
    //
    // Ánh xạ địa chỉ (addr mapping):
    //   tb_addr[6]   = 0 → ghi vào blk[] (không phải state)
    //   tb_addr[5:1] = idx[5:1] → lane index = idx/2
    //   tb_addr[0]   = idx[0]   → 0=32-bit thấp, 1=32-bit cao của lane 64-bit
    //
    // Ví dụ: idx=0 → addr={1'b0,4'b0000,1'b0}=0x00 → blk[0][31:0]
    //        idx=1 → addr={1'b0,4'b0000,1'b1}=0x01 → blk[0][63:32]
    //        idx=2 → addr={1'b0,4'b0001,1'b0}=0x02 → blk[1][31:0]
    // ================================================================
    task write_word;
        input integer idx;
        input [31:0]  data;
        begin
            tb_addr    = {1'b0, idx[5:1], idx[0]};  // Tạo địa chỉ từ word index
            tb_wr_data = data;
            tb_we      = 1;
            #(CLK_PERIOD);   // Giữ we=1 trong 1 clock để RTL latch
        end
    endtask

    // ================================================================
    // TASK: pump_init
    // Phát xung init 1 clock → DUT absorb block đầu vào state
    // Sau đó chờ busy (ready=0) → ready=1 (24 vòng Keccak hoàn thành)
    //
    // init=1 → RTL: st[i] = blk[i]  (ghi đè toàn bộ state)
    // round đặt về 0, ready về 0
    // Sau 24 clock: round=23 → ready về 1
    // ================================================================
    task pump_init;
        reg p;
        begin
            tb_we=0;
            tb_dut_init=1; #(CLK_PERIOD);   // Xung init 1 clock
            tb_dut_init=0;
            // Polling: chờ DUT báo xong (ready=1)
            p=1;
            while(p) begin
                #(CLK_PERIOD);
                p=(tb_rdy!==1'b1);
            end
        end
    endtask

    // ================================================================
    // TASK: pump_next
    // Giống pump_init nhưng dùng next thay vì init
    // Dùng cho block thứ 2 trở đi (multi-block message)
    //
    // next=1 → RTL: st[i] = st[i] XOR blk[i]  (absorb XOR vào state cũ)
    // Đây là bước absorb chuẩn của Sponge construction
    // ================================================================
    task pump_next;
        reg p;
        begin
            tb_we=0;
            tb_dut_next=1; #(CLK_PERIOD);   // Xung next 1 clock
            tb_dut_next=0;
            // Polling: chờ DUT báo xong
            p=1;
            while(p) begin
                #(CLK_PERIOD);
                p=(tb_rdy!==1'b1);
            end
        end
    endtask

    // ================================================================
    // TASK: check
    // So sánh output_words word từ DUT với giá trị hash reference
    //
    // Đọc từng word từ state (addr[6]=1) theo thứ tự:
    //   i=0: tb_addr={1'b1,5'b0,1'b0} → st[0][31:0]   (MSB của hash)
    //   i=1: tb_addr={1'b1,5'b0,1'b1} → st[0][63:32]
    //   i=2: tb_addr={1'b1,5'b1,1'b0} → st[1][31:0]
    //   ...
    // hash_shreg shift trái 32-bit sau mỗi so sánh để lấy ref word tiếp theo
    // ================================================================
    task check;
        input [511:0] ref_hash;
        begin
            mismatch=0;
            hash_shreg=ref_hash;  // Load full 512-bit ref vào shift register

            for(i=0; i<output_words; i=i+1) begin
                // Đọc word thứ i từ state của DUT
                tb_addr={1'b1,i[5:1],i[0]};
                tb_we=0;
                #(CLK_PERIOD);
                hash_word=tb_rd_data;

                // So sánh với 32-bit MSB hiện tại của ref
                $display("    word[%2d]  ref=%08h  got=%08h  %s",
                    i, hash_shreg[511-:32], hash_word,
                    (hash_shreg[511-:32]!==hash_word)?"*** FAIL":"ok");

                // Ghi nhận lỗi
                if(hash_shreg[511-:32]!==hash_word) begin
                    mismatch=1;
                    num_err=num_err+1;
                end

                // Dịch ref sang trái 32-bit để chuẩn bị so sánh word tiếp
                hash_shreg={hash_shreg[479:0],{32{1'b0}}};
            end

            tb_addr=0; tb_we=0;  // Reset bus
            if(mismatch) $display("    *** FAILED\n");
            else         $display("    *** PASSED\n");
        end
    endtask

    // ================================================================
    // TASK: set_variant
    // Chọn SHA3 variant (224/256/384/512) và cập nhật các tham số tb
    //
    // PHẢI GỌI TRƯỚC gen_load() vì:
    //   gen.set_variant(v) → cập nhật blk_bytes trong sha3_bank
    //   gen_load() → do_pad() dùng blk_bytes để tính padding
    //   Nếu gọi sai thứ tự: blk_bytes=0 → plen sai → padding sai → FAIL
    //
    // v: 2-bit variant ID (V224=0, V256=1, V384=2, V512=3)
    // osz: số bit output của variant đó
    // ================================================================
    task set_variant;
        input [1:0]   v;
        input integer osz;
        begin
            gen.set_variant(v);           // Cập nhật blk_bytes trong sha3_bank
            block_words  = gen.gen_block_words;   // Lưu vào biến tb để dùng sau
            output_words = osz >> 5;              // osz/32 = số word cần đọc
        end
    endtask

    // ================================================================
    // TASK: fill_from_gen
    // Ghi nội dung của 1 block từ gen_words[] vào DUT (blk[])
    //
    // Luôn ghi đủ MAX_BLOCK_WORDS (36) word dù block_words có thể nhỏ hơn:
    //   i < gen_block_words : ghi word thực từ gen_words[blk_num × blk_words + i]
    //   i >= gen_block_words: ghi 0x00000000 để clear vùng ngoài rate
    //
    // Lý do phải clear vùng ngoài rate:
    //   RTL blk[] không tự xóa giữa các test
    //   Nếu test SHA3-224 (36 words) chạy trước, lane 17 còn dữ liệu cũ
    //   Test SHA3-256 sau (34 words) sẽ absorb lane 17 cũ → hash sai
    //
    // blk_num: chỉ số block cần ghi (0=block đầu, 1=block thứ 2, ...)
    // ================================================================
    task fill_from_gen;
        input integer blk_num;
        begin
            #(4*CLK_PERIOD);   // Delay nhỏ để tín hiệu ổn định
            for(i=0; i<MAX_BLOCK_WORDS; i=i+1) begin
                if(i < gen.gen_block_words)
                    // Ghi word thực: đọc từ gen_words[] qua hàm gen_block_word()
                    write_word(i, gen.gen_block_word(blk_num, i));
                else
                    // Clear vùng ngoài rate: tránh dữ liệu cũ từ test trước
                    write_word(i, 32'h00000000);
            end
            tb_we=0; tb_addr=0;   // Reset bus sau khi ghi xong
        end
    endtask

    // ================================================================
    // TASK: run_from_gen  ← ENTRY POINT CHÍNH cho single-block test
    // Thực hiện đầy đủ 1 test case:
    //   fill_from_gen(0) → ghi block 0 vào DUT
    //   pump_init()      → DUT absorb + 24 vòng Keccak
    //   check(ref)       → so sánh output với giá trị chuẩn
    //
    // Dùng cho: G1-G6, G10-G15 (message vừa đủ 1 block sau padding)
    // Caller phải đảm bảo: set_variant() và gen.gen_load() đã gọi trước
    // ================================================================
    task run_from_gen;
        input [511:0] ref;
        begin
            fill_from_gen(0);   // Ghi block 0 (và duy nhất)
            pump_init();         // Absorb + tính hash
            check(ref);          // Kiểm tra kết quả
        end
    endtask

    // ================================================================
    // TASK: run_long_gen  ← ENTRY POINT cho multi-block test (G8, G9)
    // Xử lý message 200 byte — luôn cần nhiều hơn 1 block với mọi variant
    //
    // val: byte lặp lại (0xA3 cho G8, 0x00 cho G9)
    // total_bits = 200×8 = 1600 → đếm ngược khi ghi
    //
    // Luồng xử lý:
    //   Block 0: ghi fill × block_words + clear vùng ngoài → pump_init()
    //   Block 1+: ghi tiếp data còn lại hoặc padding → pump_next()
    //     - total_bits > 0: tiếp tục ghi fill
    //     - total_bits = 0: ghi padding (0x06... 0x80)
    //       + Nếu padding vừa khít 1 word cuối: 0x06000080, done=1
    //       + Nếu padding trải qua nhiều word: 0x06000000 ở đầu, 0x80 ở cuối
    //
    // Lưu ý gọi set_variant() trước khi gọi task này để block_words đúng
    // ================================================================
    task run_long_gen;
        input [511:0] ref;
        input [7:0]   val;
        reg   [31:0]  fill;    // Word 32-bit = {val,val,val,val}
        integer       total_bits;
        reg           done;    // 1 khi đã ghi xong toàn bộ kể cả padding
        reg           padded;  // 1 khi đã bắt đầu ghi byte padding 0x06
        begin
            fill       = {val, val, val, val};
            total_bits = 1600;   // 200 byte × 8 bit = 1600 bit
            done   = 0;
            padded = 0;

            // --- Block 0: pump_init ---
            // Ghi đủ MAX_BLOCK_WORDS word (gồm cả clear vùng ngoài rate)
            #(4*CLK_PERIOD);
            for(i=0; i<MAX_BLOCK_WORDS; i=i+1) begin
                if(i < block_words) begin
                    write_word(i, fill);
                    total_bits = total_bits - 32;   // Trừ 32 bit đã ghi
                end else
                    write_word(i, 32'h00000000);    // Clear vùng ngoài rate
            end
            tb_we=0; tb_addr=0;
            pump_init();   // Absorb block 0 vào state

            // --- Block 1, 2, ...: pump_next cho đến khi hết data + padding ---
            while(!done) begin
                for(i=0; i<MAX_BLOCK_WORDS; i=i+1) begin
                    if(i >= block_words)
                        // Vùng ngoài rate: luôn clear
                        write_word(i, 32'h00000000);
                    else if(total_bits > 0) begin
                        // Còn data: tiếp tục ghi fill
                        write_word(i, fill);
                        total_bits = total_bits - 32;
                    end else if(!padded) begin
                        // Hết data → bắt đầu padding SHA3 (FIPS 202)
                        // 0x06: domain suffix + pad start (1 byte 0x06)
                        // 0x80: pad end bit (bit cuối cùng của block)
                        if(i == block_words-1) begin
                            // 0x06 và 0x80 vào cùng 1 word: {0x06, 0x00, 0x00, 0x80}
                            write_word(i, 32'h06000080);
                            done=1;   // Xong
                        end else
                            // 0x06 riêng, 0x80 sẽ ở word cuối
                            write_word(i, 32'h06000000);
                        padded = 1;   // Đã ghi 0x06 rồi
                    end else if(i == block_words-1) begin
                        // Word cuối block: ghi 0x80 (pad end)
                        write_word(i, 32'h00000080);
                        done=1;
                    end else
                        // Các word giữa: zero fill
                        write_word(i, 32'h00000000);
                end
                tb_we=0; tb_addr=0;
                pump_next();   // Absorb block này vào state
            end

            check(ref);   // Kiểm tra kết quả cuối
        end
    endtask


    // ================================================================
    // MAIN STIMULUS — Chạy lần lượt 15 nhóm test
    //
    // QUY TẮC BẮT BUỘC mỗi test case:
    //   set_variant(V, OSZ)   ← TRƯỚC (set blk_bytes cho sha3_bank)
    //   gen.gen_load(STR_ID)  ← SAU  (dùng blk_bytes để tính padding)
    //   run_from_gen(REF)     ← Thực thi test
    //
    // Kết quả: num_err đếm tổng word sai, in PASSED/FAILED cuối cùng
    // ================================================================
    initial begin : sha3_test

        $display("==============================================");
        $display("  SHA3 Testbench v4 -- sha3_bank based");
        $display("==============================================\n");
        num_err=0;
        init_sim();    // Khởi tạo tín hiệu
        reset_dut();   // Reset DUT về trạng thái ban đầu

        // ============================================================
        // G1: Empty message — kiểm tra padding thuần (không có data)
        // word[0] = 0x06000000, word[last] = 0x00000080, còn lại = 0
        // ============================================================
        $display("=== G1: Empty message ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_EMPTY); $display("*** Empty -- 224"); run_from_gen(H224_EMPTY);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_EMPTY); $display("*** Empty -- 256"); run_from_gen(H256_EMPTY);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_EMPTY); $display("*** Empty -- 384"); run_from_gen(H384_EMPTY);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_EMPTY); $display("*** Empty -- 512"); run_from_gen(H512_EMPTY);

        // ============================================================
        // G2: Single byte 0x00 — phân biệt empty vs null byte
        // word[0] = 0x00060000: byte 0x00 + byte 0x06 (pad) + 2 byte 0x00
        // ============================================================
        $display("=== G2: Single byte 0x00 ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_B00); $display("*** 0x00 -- 224"); run_from_gen(H224_B00);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_B00); $display("*** 0x00 -- 256"); run_from_gen(H256_B00);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_B00); $display("*** 0x00 -- 384"); run_from_gen(H384_B00);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_B00); $display("*** 0x00 -- 512"); run_from_gen(H512_B00);

        // ============================================================
        // G3: Single byte 0xFF — kiểm tra byte all-ones
        // word[0] = 0xFF060000
        // ============================================================
        $display("=== G3: Single byte 0xFF ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_BFF); $display("*** 0xFF -- 224"); run_from_gen(H224_BFF);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_BFF); $display("*** 0xFF -- 256"); run_from_gen(H256_BFF);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_BFF); $display("*** 0xFF -- 384"); run_from_gen(H384_BFF);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_BFF); $display("*** 0xFF -- 512"); run_from_gen(H512_BFF);

        // ============================================================
        // G4: 'a' — 1 ký tự ASCII, nằm trong byte đầu tiên của word[0]
        // word[0] = 0x61060000: 'a'=0x61, 0x06 pad, 2 byte 0
        // ============================================================
        $display("=== G4: Single byte 'a' ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_A); $display("*** 'a' -- 224"); run_from_gen(H224_BA);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_A); $display("*** 'a' -- 256"); run_from_gen(H256_BA);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_A); $display("*** 'a' -- 384"); run_from_gen(H384_BA);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_A); $display("*** 'a' -- 512"); run_from_gen(H512_BA);

        // ============================================================
        // G5: "abc" — 3 byte, pad ngay sau byte thứ 3 trong word đầu
        // word[0] = 0x61626306: 'a','b','c',0x06 (pad domain suffix)
        // ============================================================
        $display("=== G5: abc ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_ABC); $display("*** abc -- 224"); run_from_gen(H224_ABC);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_ABC); $display("*** abc -- 256"); run_from_gen(H256_ABC);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_ABC); $display("*** abc -- 384"); run_from_gen(H384_ABC);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_ABC); $display("*** abc -- 512"); run_from_gen(H512_ABC);

        // ============================================================
        // G6: a-z (26 byte) — trải qua 7 word (6.5 word data + 0.5 pad)
        // word[6] = 0x797A0600: 'y','z',0x06,0x00
        // ============================================================
        $display("=== G6: a-z lowercase ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_AZ_LOWER); $display("*** a-z -- 224"); run_from_gen(H224_AZ);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_AZ_LOWER); $display("*** a-z -- 256"); run_from_gen(H256_AZ);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_AZ_LOWER); $display("*** a-z -- 384"); run_from_gen(H384_AZ);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_AZ_LOWER); $display("*** a-z -- 512"); run_from_gen(H512_AZ);

        // ============================================================
        // G7: Exact block boundary — message khớp đúng 1 block
        // Đây là edge case quan trọng: padding PHẢI sang block 2
        // Block 1: toàn bộ 0xA3A3A3A3 × block_words → pump_init()
        // Block 2: padding thuần (gen.gen_load(STR_EMPTY)) → pump_next()
        // Không dùng gen.gen_load cho block 1 vì gen không hỗ trợ fill byte lặp lại
        // ============================================================
        $display("=== G7: Exact block boundary ===");

        // SHA3-256: 136 byte = 34 word data, padding sang block 2
        $display("*** Exact block 0xA3 x 136B -- 256");
        set_variant(`V256,`SHA3_256_OUTPUT_BITS);
        #(4*CLK_PERIOD);
        for(i=0;i<MAX_BLOCK_WORDS;i=i+1)
            write_word(i,(i<block_words)?32'hA3A3A3A3:32'h00000000);  // Clear vùng ngoài rate
        tb_we=0; tb_addr=0;
        pump_init();   // Absorb block 1 (toàn data)
        // Block 2: chỉ có padding — sha3_bank sinh tự động từ STR_EMPTY + variant 256
        set_variant(`V256,`SHA3_256_OUTPUT_BITS);
        gen.gen_load(`STR_EMPTY);
        fill_from_gen(0); pump_next(); check(H256_EXB);

        // SHA3-512: 72 byte = 18 word data, padding sang block 2
        $display("*** Exact block 0xA3 x 72B -- 512");
        set_variant(`V512,`SHA3_512_OUTPUT_BITS);
        #(4*CLK_PERIOD);
        for(i=0;i<MAX_BLOCK_WORDS;i=i+1)
            write_word(i,(i<block_words)?32'hA3A3A3A3:32'h00000000);
        tb_we=0; tb_addr=0;
        pump_init();
        set_variant(`V512,`SHA3_512_OUTPUT_BITS);
        gen.gen_load(`STR_EMPTY);
        fill_from_gen(0); pump_next(); check(H512_EXB);

        // ============================================================
        // G8: 200 byte 0xA3 — NIST official long message test vector
        // Dùng run_long_gen vì cần nhiều block hơn 1
        // ============================================================
        $display("=== G8: Long 200x 0xA3 ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); $display("*** 200xA3 -- 224"); run_long_gen(H224_A3,8'hA3);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); $display("*** 200xA3 -- 256"); run_long_gen(H256_A3,8'hA3);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); $display("*** 200xA3 -- 384"); run_long_gen(H384_A3,8'hA3);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); $display("*** 200xA3 -- 512"); run_long_gen(H512_A3,8'hA3);

        // ============================================================
        // G9: 200 byte 0x00 — tương tự G8 nhưng toàn byte 0
        // Kiểm tra: phân biệt data 0x00 với padding 0x00 trong blk[]
        // ============================================================
        $display("=== G9: Long 200x 0x00 ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); $display("*** 200x00 -- 224"); run_long_gen(H224_Z0,8'h00);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); $display("*** 200x00 -- 256"); run_long_gen(H256_Z0,8'h00);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); $display("*** 200x00 -- 384"); run_long_gen(H384_Z0,8'h00);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); $display("*** 200x00 -- 512"); run_long_gen(H512_Z0,8'h00);

        // ============================================================
        // G10: "Hello, World!" — chuỗi thực tế đầu tiên
        // 13 byte → 4 word (word[3]=0x21060000: '!',0x06,0x00,0x00)
        // ============================================================
        $display("=== G10: Hello, World! ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_HELLO); $display("*** Hello -- 224"); run_from_gen(H224_HW);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_HELLO); $display("*** Hello -- 256"); run_from_gen(H256_HW);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_HELLO); $display("*** Hello -- 384"); run_from_gen(H384_HW);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_HELLO); $display("*** Hello -- 512"); run_from_gen(H512_HW);

        // ============================================================
        // G11: "SHA3-256" — chuỗi 8 byte (bội số của 4) → pad vào word riêng
        // word[2]=0x06000000: chỉ có byte 0x06, 3 byte 0 còn lại
        // ============================================================
        $display("=== G11: SHA3-256 string ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_SHA3_256); $display("*** SHA3-256 -- 224"); run_from_gen(H224_S3);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_SHA3_256); $display("*** SHA3-256 -- 256"); run_from_gen(H256_S3);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_SHA3_256); $display("*** SHA3-256 -- 384"); run_from_gen(H384_S3);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_SHA3_256); $display("*** SHA3-256 -- 512"); run_from_gen(H512_S3);

        // ============================================================
        // G12: "Test@2024#!" — 11 byte (không bội số của 4)
        // word[2]=0x34232106: '4','#','!',0x06
        // ============================================================
        $display("=== G12: Test@2024#! ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_TEST_SP); $display("*** Test@2024#! -- 224"); run_from_gen(H224_SP);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_TEST_SP); $display("*** Test@2024#! -- 256"); run_from_gen(H256_SP);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_TEST_SP); $display("*** Test@2024#! -- 384"); run_from_gen(H384_SP);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_TEST_SP); $display("*** Test@2024#! -- 512"); run_from_gen(H512_SP);

        // ============================================================
        // G13: A-Z uppercase (26 byte) — đối xứng với G6
        // word[6]=0x595A0600: 'Y','Z',0x06,0x00
        // ============================================================
        $display("=== G13: A-Z uppercase ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_AZ_UPPER); $display("*** A-Z -- 224"); run_from_gen(H224_AZU);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_AZ_UPPER); $display("*** A-Z -- 256"); run_from_gen(H256_AZU);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_AZ_UPPER); $display("*** A-Z -- 384"); run_from_gen(H384_AZU);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_AZ_UPPER); $display("*** A-Z -- 512"); run_from_gen(H512_AZU);

        // ============================================================
        // G14: "!@#$%^&*()" — 10 byte ký tự đặc biệt
        // word[2]=0x28290600: '(',')',0x06,0x00
        // ============================================================
        $display("=== G14: !@#$%%^&*() ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_SPECIAL); $display("*** special -- 224"); run_from_gen(H224_PC);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_SPECIAL); $display("*** special -- 256"); run_from_gen(H256_PC);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_SPECIAL); $display("*** special -- 384"); run_from_gen(H384_PC);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_SPECIAL); $display("*** special -- 512"); run_from_gen(H512_PC);

        // ============================================================
        // G15: Pangram (43 byte) — dùng đủ 26 chữ cái tiếng Anh
        // word[10]=0x646F6706: 'd','o','g',0x06
        // ============================================================
        $display("=== G15: Pangram ===");
        set_variant(`V224,`SHA3_224_OUTPUT_BITS); gen.gen_load(`STR_PANGRAM); $display("*** Pangram -- 224"); run_from_gen(H224_PG);
        set_variant(`V256,`SHA3_256_OUTPUT_BITS); gen.gen_load(`STR_PANGRAM); $display("*** Pangram -- 256"); run_from_gen(H256_PG);
        set_variant(`V384,`SHA3_384_OUTPUT_BITS); gen.gen_load(`STR_PANGRAM); $display("*** Pangram -- 384"); run_from_gen(H384_PG);
        set_variant(`V512,`SHA3_512_OUTPUT_BITS); gen.gen_load(`STR_PANGRAM); $display("*** Pangram -- 512"); run_from_gen(H512_PG);


        // ================================================================
        // KẾT QUẢ CUỐI CÙNG
        // num_err = 0: tất cả word khớp với giá trị NIST → DUT đúng
        // num_err > 0: có word sai → xem log để debug
        // ================================================================
        $display("==============================================");
        $display("  Testbench complete. %0d groups tested.", 15);
        if(num_err==0) $display("  ALL TESTS PASSED.");
        else           $display("  %0d WORD(S) MISMATCHED.", num_err);
        $display("==============================================");
        $finish;
    end

endmodule