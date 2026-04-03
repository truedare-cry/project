//======================================================================
// tb5_sha3_demo.v — SHA3 Testbench muốn nhập chuỗi tùy ý từ ModelSim
//
// Dùng trong ModelSim:
//   vsim work.tb5_sha3_input -Lf 220model -Lf altera_mf_ver -Lf verilog \
//       +STR="ilovehcmus##" +VARIANT=256
//
// Hoặc chạy qua do file:
//   vsim ... +STR="Hello" +VARIANT=512
//
// VARIANT hợp lệ: 224, 256, 384, 512 (mặc định 256 nếu không truyền)
// STR tối đa 43 ký tự ASCII in được (0x20..0x7E)
//======================================================================

`include "sha3_bank.v"

`define SHA3_224_OUTPUT_BITS  224
`define SHA3_256_OUTPUT_BITS  256
`define SHA3_384_OUTPUT_BITS  384
`define SHA3_512_OUTPUT_BITS  512

module tb5_sha3 ();

    // ================================================================
    // TIMING
    // ================================================================
    parameter CLK_HALF_PERIOD = 2;
    parameter CLK_PERIOD      = 2 * CLK_HALF_PERIOD;
    parameter MAX_BLOCK_WORDS = 36;

    // ================================================================
    // SIGNALS
    // ================================================================
    reg         tb_clk;
    reg         tb_rst_n;
    reg         tb_we;
    reg  [6:0]  tb_addr;
    reg  [31:0] tb_wr_data;
    reg         tb_dut_init;
    reg         tb_dut_next;
    wire [31:0] tb_rd_data;
    wire        tb_rdy;

    integer     i, k;
    integer     block_words;
    integer     output_words;
    integer     variant_int;    // 224/256/384/512
    reg [1:0]   variant_id;     // V224=0 V256=1 V384=2 V512=3

    reg [511:0] hash_shreg;
    reg [31:0]  hash_word;

    // Buffer nhận chuỗi từ plusargs (tối đa 43 ký tự × 8-bit)
    // Verilog string trong reg: mỗi ký tự 8-bit, MSB = ký tự đầu
    reg [8*64-1:0] str_arg;     // Buffer 64 ký tự cho $value$plusargs
    reg [7:0]      char_buf [0:63]; // Tách ra từng byte
    integer        str_len;

    // Variant arg
    reg [8*8-1:0]  var_arg;
    integer        var_val;

    // ================================================================
    // DUT + Generator
    // ================================================================
    sha3 dut (
        .clk(tb_clk), .nreset(tb_rst_n),
        .w(tb_we),    .addr(tb_addr),
        .din(tb_wr_data), .dout(tb_rd_data),
        .init(tb_dut_init), .next(tb_dut_next),
        .ready(tb_rdy)
    );

    sha3_bank gen();

    initial tb_clk = 1'b0;
    always  #CLK_HALF_PERIOD tb_clk = ~tb_clk;

    // ================================================================
    // TASKS (giữ nguyên từ tb4)
    // ================================================================
    task write_word;
        input integer idx;
        input [31:0]  data;
        begin
            tb_addr    = {1'b0, idx[5:1], idx[0]};
            tb_wr_data = data;
            tb_we      = 1;
            #(CLK_PERIOD);
        end
    endtask

    task pump_init;
        reg p;
        begin
            tb_we=0;
            tb_dut_init=1; #(CLK_PERIOD); tb_dut_init=0;
            p=1; while(p) begin #(CLK_PERIOD); p=(tb_rdy!==1'b1); end
        end
    endtask

    task pump_next;
        reg p;
        begin
            tb_we=0;
            tb_dut_next=1; #(CLK_PERIOD); tb_dut_next=0;
            p=1; while(p) begin #(CLK_PERIOD); p=(tb_rdy!==1'b1); end
        end
    endtask

    task set_variant_id;
        input [1:0] v;
        input integer osz;
        begin
            gen.set_variant(v);
            block_words  = gen.gen_block_words;
            output_words = osz >> 5;
        end
    endtask

    task fill_from_gen;
        input integer blk_num;
        begin
            #(4*CLK_PERIOD);
            for(i=0; i<MAX_BLOCK_WORDS; i=i+1) begin
                if(i < gen.gen_block_words)
                    write_word(i, gen.gen_block_word(blk_num, i));
                else
                    write_word(i, 32'h00000000);
            end
            tb_we=0; tb_addr=0;
        end
    endtask

    // ================================================================
    // TASK: load_custom_string
    // Nạp char_buf[] vào sha3_bank theo cách thủ công (byte-by-byte)
    // vì sha3_bank chỉ hỗ trợ STR_ID cố định
    // ================================================================
    task load_custom_string;
        integer k2, plen;
        begin
            // Xóa buffer của gen
            for (k2=0; k2<256; k2=k2+1)
                gen.raw_bytes[k2] = 8'h00;

            // Copy char_buf → gen.raw_bytes
            for (k2=0; k2<str_len; k2=k2+1)
                gen.raw_bytes[k2] = char_buf[k2];

            gen.raw_len = str_len;

            // Gọi do_pad() và do_pack() trực tiếp
            gen.do_pad();
            gen.do_pack();
        end
    endtask

    // ================================================================
    // TASK: print_hash
    // In hash output dưới dạng hex liên tục (không có khoảng trắng)
    // ================================================================
    task print_hash;
        integer w_idx;
        reg [31:0] word_val;
        begin
            $display("\n============================================");
            $display("  SHA3-%0d(\"%s\")", variant_int, str_arg);
            $display("============================================");
            $write("  Hash = ");
            hash_shreg = 512'h0;
            for(w_idx=0; w_idx<output_words; w_idx=w_idx+1) begin
                tb_addr = {1'b1, w_idx[5:1], w_idx[0]};
                tb_we   = 0;
                #(CLK_PERIOD);
                word_val = tb_rd_data;
                $write("%08h", word_val);
                // Lưu vào hash_shreg để xem trên waveform
                hash_shreg = hash_shreg | (word_val << ((output_words-1-w_idx)*32));
            end
            $display("");
            $display("============================================\n");
            tb_addr=0; tb_we=0;
        end
    endtask

    // ================================================================
    // TASK: parse_str_arg
    // Tách reg[8*64-1:0] str_arg thành char_buf[] + tính str_len
    // ModelSim lưu string vào reg dạng MSB-first, null-padded
    // ================================================================
    task parse_str_arg;
        integer idx2;
        reg [7:0] ch;
        begin
            str_len = 0;
            for (idx2=63; idx2>=0; idx2=idx2-1) begin
                // Lấy byte tại vị trí idx2 (từ MSB)
                ch = str_arg[idx2*8 +: 8];
                if (ch != 8'h00) begin
                    // Đảo thứ tự: MSB-first → index 0 là ký tự đầu tiên
                    str_len = str_len + 1;
                end
            end
            // Lấy đúng str_len ký tự theo thứ tự từ MSB của str_arg
            for (idx2=0; idx2<str_len; idx2=idx2+1) begin
                // Byte tại vị trí (63-idx2) trong str_arg là ký tự thứ idx2
                char_buf[idx2] = str_arg[(63-idx2)*8 +: 8];
            end
        end
    endtask

    // ================================================================
    // MAIN
    // ================================================================
    initial begin : main_block

        // Khởi tạo
        tb_rst_n=0; tb_we=0; tb_addr=0; tb_wr_data=0;
        tb_dut_init=0; tb_dut_next=0;
        str_arg  = 0;
        var_arg  = 0;
        str_len  = 0;
        variant_int = 256;

        // ---- Đọc tham số từ plusargs ----
        // +STR="your_string"
        if (!$value$plusargs("STR=%s", str_arg)) begin
            $display("** Khong co +STR, dung mac dinh: 'abc'");
            str_arg = "abc";  // Mặc định
        end

        // +VARIANT=256
        if ($value$plusargs("VARIANT=%d", var_val))
            variant_int = var_val;
        else
            variant_int = 256;

        // Parse chuỗi
        parse_str_arg();

        // In thông tin đầu vào
        $display("\n==============================================");
        $display("  SHA3 Interactive Testbench");
        $display("  Input  : \"%s\" (%0d bytes)", str_arg, str_len);
        $display("  Variant: SHA3-%0d", variant_int);
        $display("==============================================");

        // In bảng ASCII → hex
        $display("\n  ASCII -> Hex table:");
        for (k=0; k<str_len; k=k+1)
            $display("    [%2d]  '%s'  = 0x%02h  = %08b",
                     k,
                     (char_buf[k] >= 8'h21 && char_buf[k] <= 8'h7e) ?
                         $sformatf("%c", char_buf[k]) : ".",
                     char_buf[k],
                     char_buf[k]);

        // Reset DUT
        repeat(4) @(posedge tb_clk);
        tb_rst_n=1;
        #(CLK_PERIOD);

        // Chọn variant
        case (variant_int)
            224: set_variant_id(`V224, `SHA3_224_OUTPUT_BITS);
            256: set_variant_id(`V256, `SHA3_256_OUTPUT_BITS);
            384: set_variant_id(`V384, `SHA3_384_OUTPUT_BITS);
            512: set_variant_id(`V512, `SHA3_512_OUTPUT_BITS);
            default: begin
                $display("** Variant %0d khong hop le, dung 256", variant_int);
                set_variant_id(`V256, `SHA3_256_OUTPUT_BITS);
                variant_int = 256;
            end
        endcase

        // Load chuỗi vào generator
        load_custom_string();

        // In word list sau padding
        $display("\n  32-bit words (big-endian, sau padding):");
        for (k=0; k<gen.gen_nwords; k=k+1)
            $display("    w[%2d] = 0x%08h", k, gen.gen_words[k]);

        // Ghi block 0 vào DUT → pump_init
        fill_from_gen(0);
        pump_init();

        // Nếu có block 2 (multi-block) → pump_next
        if (gen.gen_total_blocks > 1) begin
            fill_from_gen(1);
            pump_next();
        end

        // In kết quả hash
        print_hash();

        $display("  [Xem waveform: hash_shreg chua ket qua tren wave]");
        $display("==============================================\n");

        #(8*CLK_PERIOD);
        $finish;
    end

    // ================================================================
    // WAVE MONITOR: hiển thị hash_shreg trên waveform khi có kết quả
    // ================================================================
    // (hash_shreg được gán trong print_hash() nên xuất hiện trên wave)

endmodule