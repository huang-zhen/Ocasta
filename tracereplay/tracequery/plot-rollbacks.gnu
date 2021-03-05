set term postscript eps blacktext "Helvetica" 24
set output 'rollbacks.eps'
set xlabel 'Thresholds'
set ylabel 'Reduction of Rollbacks'
# set xtics 4096
set logscale x
plot "afshar.Explorer.EXE.1" using 1:2 title "1" with lines linecolor 1, "afshar.Explorer.EXE.2" using 1:2 title "2" with lines linecolor 2
set output
quit

