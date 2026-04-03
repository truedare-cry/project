//======================================================================
// sha3_bank.v
//
// Mục đích : Nhận chuỗi ASCII (hard-code hoặc qua parameter),
//            tự động:
//              1. Chuyển từng byte sang hex (bảng ASCII)
//              2. Đóng gói big-endian 32-bit word
//              3. Chèn SHA3 padding (FIPS 202: 0x06 ... 0x80)
//              4. Cung cấp interface sạch cho tb đọc word
//
// Interface với testbench:
//   - gen_load(str_id)     : nạp chuỗi theo ID
//   - gen_get_word(idx)    → word[idx] đã pad sẵn
//   - gen_block_words      : số word / block của variant đang chọn
//   - gen_total_blocks     : số block cần pump
//   - gen_block_word(blk,idx) → word[idx] của block blk
//
// Cách dùng trong tb:
//   gen_load(STR_HELLO);          // nạp "Hello, World!"
//   set_variant(SHA3_256);        // chọn variant
//   run_from_gen(H256_HW, ...);   // tb tự fill + pump + check
//======================================================================

`ifndef SHA3_BANK
`define SHA3_BANK

//----------------------------------------------------------------------
// Macro: định nghĩa variant ID
//----------------------------------------------------------------------
`define V224  2'd0
`define V256  2'd1
`define V384  2'd2
`define V512  2'd3

//----------------------------------------------------------------------
// Block bytes theo variant
//   224 → 144B = 36 words
//   256 → 136B = 34 words
//   384 → 104B = 26 words
//   512 →  72B = 18 words
//----------------------------------------------------------------------
`define BLKBYTES_224  8'd144
`define BLKBYTES_256  8'd136
`define BLKBYTES_384  8'd104
`define BLKBYTES_512  8'd72

//----------------------------------------------------------------------
// String ID — thêm chuỗi mới ở đây, không cần sửa chỗ nào khác
//----------------------------------------------------------------------
`define STR_EMPTY      5'd0
`define STR_B00        5'd1   // 0x00
`define STR_BFF        5'd2   // 0xFF
`define STR_A          5'd3   // 'a'
`define STR_ABC        5'd4   // "abc"
`define STR_AZ_LOWER   5'd5   // "abcdefghijklmnopqrstuvwxyz"
`define STR_AZ_UPPER   5'd6   // "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
`define STR_HELLO      5'd7   // "Hello, World!"
`define STR_SHA3_256   5'd8   // "SHA3-256"
`define STR_TEST_SP    5'd9   // "Test@2024#!"
`define STR_SPECIAL    5'd10  // "!@#$%^&*()"
`define STR_PANGRAM    5'd11  // "The quick brown fox jumps over the lazy dog"
// ---- Thêm chuỗi tùy ý ----
`define STR_CUSTOM0    5'd12  // "ilovehcmus##"
`define STR_CUSTOM1    5'd13  // dư
`define STR_CUSTOM2    5'd14  // dư

module sha3_bank;

    //------------------------------------------------------------------
    // Internal storage
    //   raw_bytes : chuỗi ASCII gốc (tối đa 256 byte)
    //   pad_buf   : buffer sau khi pad (tối đa 2 block = 288 byte)
    //   gen_words : mảng word 32-bit sẵn sàng để ghi lên SHA3 core
    //------------------------------------------------------------------
    reg [7:0]  raw_bytes [0:255];
    reg [7:0]  pad_buf   [0:287];
    reg [31:0] gen_words [0:71];   // 2 block × 36 words max

    integer    raw_len;            // số byte thực của chuỗi
    integer    pad_len;            // tổng byte sau padding (bội của blk_bytes)
    integer    gen_nwords;         // tổng số word = pad_len/4

    reg [1:0]  cur_variant;        // variant đang chọn
    reg [7:0]  blk_bytes;          // block size (byte)
    integer    blk_words_int;      // block size (word)
    integer    total_blocks_int;   // số block

    // Public read signals (tb dùng trực tiếp)
    integer    gen_block_words;
    integer    gen_total_blocks;

    //------------------------------------------------------------------
    // TASK: set_variant
    //   Gọi trước gen_load để chọn SHA3-224/256/384/512
    //------------------------------------------------------------------
    task set_variant;
        input [1:0] v;
        begin
            cur_variant = v;
            case (v)
                `V224: begin blk_bytes = `BLKBYTES_224; end
                `V256: begin blk_bytes = `BLKBYTES_256; end
                `V384: begin blk_bytes = `BLKBYTES_384; end
                `V512: begin blk_bytes = `BLKBYTES_512; end
            endcase
            blk_words_int    = blk_bytes / 4;
            gen_block_words  = blk_words_int;
        end
    endtask

    //------------------------------------------------------------------
    // TASK: load_string_id
    //   Đặt raw_bytes[] và raw_len theo STR_* ID
    //   *** THÊM CHUỖI MỚI: thêm 1 case ở đây ***
    //------------------------------------------------------------------
    task load_string_id;
        input [4:0] str_id;
        integer k;
        begin
            // Xóa buffer
            for (k = 0; k < 256; k = k + 1) raw_bytes[k] = 8'h00;

            case (str_id)
                //------------------------------------------------------
                `STR_EMPTY: begin
                    raw_len = 0;
                end
                //------------------------------------------------------
                `STR_B00: begin
                    raw_bytes[0] = 8'h00; raw_len = 1;
                end
                //------------------------------------------------------
                `STR_BFF: begin
                    raw_bytes[0] = 8'hFF; raw_len = 1;
                end
                //------------------------------------------------------
                `STR_A: begin
                    raw_bytes[0] = "a"; raw_len = 1;
                end
                //------------------------------------------------------
                `STR_ABC: begin
                    raw_bytes[0]="a"; raw_bytes[1]="b"; raw_bytes[2]="c";
                    raw_len = 3;
                end
                //------------------------------------------------------
                `STR_AZ_LOWER: begin
                    raw_bytes[ 0]="a"; raw_bytes[ 1]="b"; raw_bytes[ 2]="c";
                    raw_bytes[ 3]="d"; raw_bytes[ 4]="e"; raw_bytes[ 5]="f";
                    raw_bytes[ 6]="g"; raw_bytes[ 7]="h"; raw_bytes[ 8]="i";
                    raw_bytes[ 9]="j"; raw_bytes[10]="k"; raw_bytes[11]="l";
                    raw_bytes[12]="m"; raw_bytes[13]="n"; raw_bytes[14]="o";
                    raw_bytes[15]="p"; raw_bytes[16]="q"; raw_bytes[17]="r";
                    raw_bytes[18]="s"; raw_bytes[19]="t"; raw_bytes[20]="u";
                    raw_bytes[21]="v"; raw_bytes[22]="w"; raw_bytes[23]="x";
                    raw_bytes[24]="y"; raw_bytes[25]="z";
                    raw_len = 26;
                end
                //------------------------------------------------------
                `STR_AZ_UPPER: begin
                    raw_bytes[ 0]="A"; raw_bytes[ 1]="B"; raw_bytes[ 2]="C";
                    raw_bytes[ 3]="D"; raw_bytes[ 4]="E"; raw_bytes[ 5]="F";
                    raw_bytes[ 6]="G"; raw_bytes[ 7]="H"; raw_bytes[ 8]="I";
                    raw_bytes[ 9]="J"; raw_bytes[10]="K"; raw_bytes[11]="L";
                    raw_bytes[12]="M"; raw_bytes[13]="N"; raw_bytes[14]="O";
                    raw_bytes[15]="P"; raw_bytes[16]="Q"; raw_bytes[17]="R";
                    raw_bytes[18]="S"; raw_bytes[19]="T"; raw_bytes[20]="U";
                    raw_bytes[21]="V"; raw_bytes[22]="W"; raw_bytes[23]="X";
                    raw_bytes[24]="Y"; raw_bytes[25]="Z";
                    raw_len = 26;
                end
                //------------------------------------------------------
                `STR_HELLO: begin
                    // "Hello, World!" — 13 bytes
                    raw_bytes[ 0]="H"; raw_bytes[ 1]="e"; raw_bytes[ 2]="l";
                    raw_bytes[ 3]="l"; raw_bytes[ 4]="o"; raw_bytes[ 5]=",";
                    raw_bytes[ 6]=" "; raw_bytes[ 7]="W"; raw_bytes[ 8]="o";
                    raw_bytes[ 9]="r"; raw_bytes[10]="l"; raw_bytes[11]="d";
                    raw_bytes[12]="!";
                    raw_len = 13;
                end
                //------------------------------------------------------
                `STR_SHA3_256: begin
                    // "SHA3-256" — 8 bytes
                    raw_bytes[0]="S"; raw_bytes[1]="H"; raw_bytes[2]="A";
                    raw_bytes[3]="3"; raw_bytes[4]="-"; raw_bytes[5]="2";
                    raw_bytes[6]="5"; raw_bytes[7]="6";
                    raw_len = 8;
                end
                //------------------------------------------------------
                `STR_TEST_SP: begin
                    // "Test@2024#!" — 11 bytes
                    raw_bytes[ 0]="T"; raw_bytes[ 1]="e"; raw_bytes[ 2]="s";
                    raw_bytes[ 3]="t"; raw_bytes[ 4]="@"; raw_bytes[ 5]="2";
                    raw_bytes[ 6]="0"; raw_bytes[ 7]="2"; raw_bytes[ 8]="4";
                    raw_bytes[ 9]="#"; raw_bytes[10]="!";
                    raw_len = 11;
                end
                //------------------------------------------------------
                `STR_SPECIAL: begin
                    // "!@#$%^&*()" — 10 bytes
                    raw_bytes[0]="!"; raw_bytes[1]="@"; raw_bytes[2]="#";
                    raw_bytes[3]="$"; raw_bytes[4]="%"; raw_bytes[5]="^";
                    raw_bytes[6]="&"; raw_bytes[7]="*"; raw_bytes[8]="(";
                    raw_bytes[9]=")";
                    raw_len = 10;
                end
                //------------------------------------------------------
                `STR_PANGRAM: begin
                    // "The quick brown fox jumps over the lazy dog" — 43 bytes
                    raw_bytes[ 0]="T"; raw_bytes[ 1]="h"; raw_bytes[ 2]="e";
                    raw_bytes[ 3]=" "; raw_bytes[ 4]="q"; raw_bytes[ 5]="u";
                    raw_bytes[ 6]="i"; raw_bytes[ 7]="c"; raw_bytes[ 8]="k";
                    raw_bytes[ 9]=" "; raw_bytes[10]="b"; raw_bytes[11]="r";
                    raw_bytes[12]="o"; raw_bytes[13]="w"; raw_bytes[14]="n";
                    raw_bytes[15]=" "; raw_bytes[16]="f"; raw_bytes[17]="o";
                    raw_bytes[18]="x"; raw_bytes[19]=" "; raw_bytes[20]="j";
                    raw_bytes[21]="u"; raw_bytes[22]="m"; raw_bytes[23]="p";
                    raw_bytes[24]="s"; raw_bytes[25]=" "; raw_bytes[26]="o";
                    raw_bytes[27]="v"; raw_bytes[28]="e"; raw_bytes[29]="r";
                    raw_bytes[30]=" "; raw_bytes[31]="t"; raw_bytes[32]="h";
                    raw_bytes[33]="e"; raw_bytes[34]=" "; raw_bytes[35]="l";
                    raw_bytes[36]="a"; raw_bytes[37]="z"; raw_bytes[38]="y";
                    raw_bytes[39]=" "; raw_bytes[40]="d"; raw_bytes[41]="o";
                    raw_bytes[42]="g";
                    raw_len = 43;
                end
                //------------------------------------------------------
                // *** THÊM CHUỖI TÙY Ý TẠI ĐÂY ***
                //------------------------------------------------------
                `STR_CUSTOM0: begin
                    // "ilovehcmus##" — 12 bytes
                    raw_bytes[ 0]="i"; raw_bytes[ 1]="l"; raw_bytes[ 2]="o";
                    raw_bytes[ 3]="v"; raw_bytes[ 4]="e"; raw_bytes[ 5]="h";
                    raw_bytes[ 6]="c"; raw_bytes[ 7]="m"; raw_bytes[ 8]="u";
                    raw_bytes[ 9]="s"; raw_bytes[10]="#"; raw_bytes[11]="#";
                    raw_len = 12;
                end
                //------------------------------------------------------
                `STR_CUSTOM1: begin
                    // Dự phòng — điền chuỗi mới vào đây
                    raw_len = 0;
                end
                `STR_CUSTOM2: begin
                    raw_len = 0;
                end
                //------------------------------------------------------
                default: raw_len = 0;
            endcase
        end
    endtask

    //------------------------------------------------------------------
    // TASK: do_pad
    //   Áp dụng SHA3 padding vào pad_buf[]
    //   Gọi sau load_string_id() và set_variant()
    //------------------------------------------------------------------
    task do_pad;
        integer k, plen;
        begin
            // Copy raw bytes
            for (k = 0; k < 288; k = k + 1) pad_buf[k] = 8'h00;
            for (k = 0; k < raw_len; k = k + 1)
                pad_buf[k] = raw_bytes[k];

            // Tính padded length (bội số của blk_bytes)
            plen = ((raw_len / blk_bytes) + 1) * blk_bytes;
            pad_len = plen;
            total_blocks_int = plen / blk_bytes;
            gen_total_blocks = total_blocks_int;

            // SHA3 padding (FIPS 202)
            pad_buf[raw_len] = 8'h06;          // domain + pad start
            pad_buf[plen - 1] = pad_buf[plen - 1] | 8'h80;  // pad end
        end
    endtask

    //------------------------------------------------------------------
    // TASK: do_pack
    //   Đóng gói pad_buf[] → gen_words[] (big-endian 32-bit)
    //   Gọi sau do_pad()
    //------------------------------------------------------------------
    task do_pack;
        integer k;
        begin
            gen_nwords = pad_len / 4;
            for (k = 0; k < gen_nwords; k = k + 1) begin
                gen_words[k] = { pad_buf[k*4],
                                 pad_buf[k*4+1],
                                 pad_buf[k*4+2],
                                 pad_buf[k*4+3] };
            end
        end
    endtask

    //------------------------------------------------------------------
    // TASK: gen_load  ← ENTRY POINT CHÍNH
    //   Gọi 1 lần duy nhất: nạp chuỗi + pad + pack
    //   Sau khi gọi xong, gen_words[] và gen_block_words sẵn sàng
    //------------------------------------------------------------------
    task gen_load;
        input [4:0] str_id;
        begin
            load_string_id(str_id);
            do_pad();
            do_pack();
        end
    endtask

    //------------------------------------------------------------------
    // FUNCTION: gen_get_word(word_index)
    //   Trả về word tại vị trí toàn cục (qua toàn bộ block)
    //------------------------------------------------------------------
    function [31:0] gen_get_word;
        input integer idx;
        begin
            gen_get_word = gen_words[idx];
        end
    endfunction

    //------------------------------------------------------------------
    // FUNCTION: gen_block_word(block_num, word_in_block)
    //   Trả về word[idx] trong block blk_num
    //------------------------------------------------------------------
    function [31:0] gen_block_word;
        input integer blk_num;
        input integer word_idx;
        begin
            gen_block_word = gen_words[blk_num * blk_words_int + word_idx];
        end
    endfunction

    //------------------------------------------------------------------
    // TASK: gen_print_hex
    //   Debug: in bảng ASCII→hex + word list
    //------------------------------------------------------------------
    task gen_print_hex;
        integer k;
        reg [7:0] b;
        begin
            $display("  [gen] raw_len=%0d  pad_len=%0d  blk_bytes=%0d  blocks=%0d",
                     raw_len, pad_len, blk_bytes, gen_total_blocks);
            $display("  [gen] ASCII → Hex:");
            for (k = 0; k < raw_len; k = k + 1) begin
                b = raw_bytes[k];
                $display("    [%2d] '%s'(0x%02h) = %08b", k,
                         (b >= 8'h21 && b <= 8'h7e) ? $sformatf("%c",b) : ".",
                         b, b);
            end
            $display("  [gen] 32-bit words:");
            for (k = 0; k < gen_nwords; k = k + 1)
                $display("    w[%2d] = 0x%08h", k, gen_words[k]);
        end
    endtask

endmodule

`endif // SHA3_BANK