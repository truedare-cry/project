onerror {resume}
quietly WaveActivateNextPane {} 0
add wave -noupdate /tb2_sha3/tb_clk
add wave -noupdate /tb2_sha3/tb_rst_n
add wave -noupdate /tb2_sha3/tb_dut_init
add wave -noupdate /tb2_sha3/tb_dut_next
add wave -noupdate /tb2_sha3/tb_rdy
add wave -noupdate /tb2_sha3/tb_we
add wave -noupdate -radix hexadecimal /tb2_sha3/tb_addr
add wave -noupdate -radix hexadecimal /tb2_sha3/tb_wr_data
add wave -noupdate -radix hexadecimal /tb2_sha3/tb_rd_data
add wave -noupdate -radix unsigned /tb2_sha3/dut/round
add wave -noupdate -radix hexadecimal /tb2_sha3/dut/blk
add wave -noupdate -radix hexadecimal /tb2_sha3/dut/st
TreeUpdate [SetDefaultTree]
WaveRestoreCursors {{Cursor 1} {8474 ps} 0}
quietly wave cursor active 1
configure wave -namecolwidth 150
configure wave -valuecolwidth 100
configure wave -justifyvalue left
configure wave -signalnamewidth 0
configure wave -snapdistance 10
configure wave -datasetprefix 0
configure wave -rowmargin 4
configure wave -childrowmargin 2
configure wave -gridoffset 0
configure wave -gridperiod 1
configure wave -griddelta 40
configure wave -timeline 0
configure wave -timelineunits ps
update
WaveRestoreZoom {8474 ps} {8476 ps}
