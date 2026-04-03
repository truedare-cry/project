# ======================================================================
# run4_sim.do — ModelSim script cho tb4_sha3 + sha3_bank
# Dùng: trong ModelSim console gõ: do run4_sim.do
# ======================================================================

quit -sim
if {[file exists work]} { vdel -all }
vlib work

# ---- Compile: chỉ 2 file, tb4_sha3.v tự `include sha3_bank.v ----
vlog -nolock sha3.v
vlog -nolock sha3_bank.v
vlog -nolock tb4_sha3.v

# ---- Khởi động simulation ----
vsim work.tb4_sha3 -Lf 220model -Lf altera_mf_ver -Lf verilog

# ======================================================================
# WAVE: Clock / Reset
# ======================================================================
add wave                 /tb4_sha3/tb_clk
add wave                 /tb4_sha3/tb_rst_n

# ======================================================================
# WAVE: SHA3 Core Control
# ======================================================================
add wave                 /tb4_sha3/tb_dut_init
add wave                 /tb4_sha3/tb_dut_next
add wave                 /tb4_sha3/tb_rdy

# ======================================================================
# WAVE: SHA3 Core Bus
# ======================================================================
add wave                 /tb4_sha3/tb_we
add wave -radix hex      /tb4_sha3/tb_addr
add wave -radix hex      /tb4_sha3/tb_wr_data
add wave -radix hex      /tb4_sha3/tb_rd_data

# ======================================================================
# WAVE: SHA3 Core Internal
# ======================================================================
add wave -radix hex      /tb4_sha3/dut/blk
add wave -radix hex      /tb4_sha3/dut/st
add wave -radix unsigned /tb4_sha3/dut/round

# ======================================================================
# WAVE: sha3_bank (generator) — instance tên "gen"
# ======================================================================
add wave -radix unsigned /tb4_sha3/gen/raw_len
add wave -radix unsigned /tb4_sha3/gen/pad_len
add wave -radix unsigned /tb4_sha3/gen/blk_bytes
add wave -radix unsigned /tb4_sha3/gen/gen_block_words
add wave -radix unsigned /tb4_sha3/gen/gen_total_blocks
add wave -radix hex      /tb4_sha3/gen/gen_words

# ======================================================================
# WAVE: TB trạng thái
# ======================================================================
add wave -radix unsigned /tb4_sha3/block_words
add wave -radix unsigned /tb4_sha3/output_words
add wave -radix unsigned /tb4_sha3/num_err
add wave                 /tb4_sha3/mismatch

# ---- Chạy toàn bộ simulation ----
run -all

# ---- Zoom fit toàn bộ waveform ----
wave zoom full
