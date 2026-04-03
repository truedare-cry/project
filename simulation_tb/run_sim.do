quit -sim
if {[file exists work]} { vdel -all }
vlib work

vlog -nolock D:/DATN/sha3.v
vlog -nolock tb_sha3.v

vsim work.tb_sha3 -Lf 220model -Lf altera_mf_ver -Lf verilog

# Xem Wave - bo divider vi ModelSim cu khong ho tro
add wave /tb_sha3/tb_clk
add wave /tb_sha3/tb_rst_n
add wave /tb_sha3/tb_dut_init
add wave /tb_sha3/tb_dut_next
add wave /tb_sha3/tb_rdy
add wave /tb_sha3/tb_we
add wave -radix hex /tb_sha3/tb_addr
add wave -radix hex /tb_sha3/tb_wr_data
add wave -radix hex /tb_sha3/tb_rd_data
add wave -radix unsigned /tb_sha3/dut/round
add wave -radix hex /tb_sha3/dut/blk
add wave -radix hex /tb_sha3/dut/st

# Chay simulation
run -all

# Zoom fit toan bo waveform
wave zoom full
