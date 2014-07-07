set terminal pdfcairo enhanced solid font "Helvetica,10"
set output "cve_nist.pdf"

set grid noxtics nomxtics noytics nomytics front

set title "Memory Errors 2003-now CVEs (http://nvd.nist.gov)"

set xdata time
set timefmt "%Y-%m"

#set xlabel "Date"
set  ylabel "Vulnerabilities"

set format x "%Y"

set xtics nomirror
set ytics nomirror

set yrange [0:400]
set ytics 50

set style fill transparent solid 0.5 

set linestyle 20 lt 1 lw 5 pt 3 ps 0.5 lc 7

set linetype 6 lc 6
set linetype 5 lc 5
set linetype 4 lc 4
set linetype 3 lc 3
set linetype 2 lc 2
set linetype 1 lc 1

today = system("date +%Y-%m")
set xrange ["2003-03":today]

plot "cve_nist.dat"    using 1:($7+$6+$5+$4+$3+$2) title "other types of overflow (lack of classification)" w filledcurve x1 linetype 6, \
     "cve_nist.dat"    using 1:($6+$5+$4+$3+$2) title "format string vulnerabilities" w filledcurve x1 linetype 5, \
     "cve_nist.dat"    using 1:($5+$4+$3+$2) title "null dereference vulnerabilities" w filledcurve x1 linetype 4, \
     "cve_nist.dat"    using 1:($4+$3+$2) title "integer or off-by-one overflows" w filledcurve x1 linetype 3, \
     "cve_nist.dat"    using 1:($2+$3) title "heap-based overflows" w filledcurve x1 linetype 2, \
     "cve_nist.dat"    using 1:($2) title "stack-based overflows" w filledcurve x1 linetype 1, \
     "cve_nist_criteria.dat"  using 1:2 title "use-after-free vulnerabilities" w lines ls 20

