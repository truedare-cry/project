# ======================================================================
# run5_sim.do — Nhập chuỗi tùy ý từ ModelSim, xem dạng sóng hash
#
# CÁCH DÙNG:
#   Sửa 2 dòng STR và VARIANT bên dưới rồi gõ: do run5_sim.do
#
# Ví dụ:
#   set INPUT_STR  "ilovehcmus##"
#   set INPUT_VAR  256
# ======================================================================

quit -sim
if {[file exists work]} { vdel -all }
vlib work

# ---- Compile ----
vlog -nolock sha3.v
vlog -nolock sha3_bank.v
vlog -nolock tb5_sha3.sv

# ======================================================================
# *** DEMO THAY ĐỔI CHUỖI VÀ VARIANT ***
# ======================================================================
set INPUT_STR  "ilovehcmus##"
set INPUT_VAR  256
# ======================================================================

# Khởi động simulation với plusargs
vsim work.tb5_sha3 \
    -Lf 220model -Lf altera_mf_ver -Lf verilog \
    "+STR=$INPUT_STR" \
    "+VARIANT=$INPUT_VAR"

# ======================================================================
# WAVE: Clock / Reset
# ======================================================================

add wave                  /tb5_sha3/tb_clk
add wave                  /tb5_sha3/tb_rst_n

# ======================================================================
# WAVE: SHA3 Core Control
# ======================================================================

add wave                  /tb5_sha3/tb_dut_init
add wave                  /tb5_sha3/tb_dut_next
add wave                  /tb5_sha3/tb_rdy
add wave -radix unsigned  /tb5_sha3/dut/round

# ======================================================================
# WAVE: Bus Ghi/Đọc
# ======================================================================

add wave                  /tb5_sha3/tb_we
add wave -radix hex       /tb5_sha3/tb_addr
add wave -radix hex       /tb5_sha3/tb_wr_data


add wave -radix hex       /tb5_sha3/tb_rd_data

# ======================================================================
# WAVE: SHA3 Core Internal
# ======================================================================
add wave -radix hex       /tb5_sha3/dut/blk
add wave -radix hex       /tb5_sha3/dut/st

# ======================================================================
# WAVE: Generator (sha3_bank)
# ======================================================================
add wave -radix unsigned  /tb5_sha3/gen/raw_len
add wave -radix unsigned  /tb5_sha3/gen/blk_bytes
add wave -radix unsigned  /tb5_sha3/gen/pad_len
add wave -radix unsigned  /tb5_sha3/gen/gen_block_words
add wave -radix hex       /tb5_sha3/gen/gen_words

# ======================================================================
# WAVE: Kết quả Hash
# ======================================================================
add wave -radix hex       /tb5_sha3/hash_shreg
add wave -radix hex       /tb5_sha3/hash_word
add wave -radix unsigned  /tb5_sha3/variant_int
add wave -radix unsigned  /tb5_sha3/str_len

# ---- Chạy ----
run -all
wave zoom full
