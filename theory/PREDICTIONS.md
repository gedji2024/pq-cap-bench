# Theorem-3 predictions (written BEFORE reading any H3/H4 result)

Generated from the stage series, NWS levels and config constants only (theory/bound.py, bound_adaptive.py, floor_time.py); harm.simulate is never called.

K = (SOC0 - 20)/100 * 1300 uplinks above the floor (LWL01 poor coverage). Window peak at day 5 for all 41 events.

Closed form: B* = (K - 1 - 24*d_c - A)/(d_c + 1), d_c = 4 (crossings on the rising limb, day before the peak), A >= 0 alert-mode uplinks.
A = 0 gives B* = 32.6 (SOC0 40), 84.6 (SOC0 60), 136.6 (SOC0 80).

P1 (proved, Theorem 3): for every B and SOC0, observed excess late-or-missed share <= P_upper(B) (tables below, column P_upper; threshold mode 'actual' for the simulated drain strategy, 'band_lo' for any C1 adversary that also moves the threshold).
P2 (heuristic, relies on the drain strategy being near-tight on uplink count): the observed jump in excess occurs at the first grid budget >= B*: SOC0 60 -> 85; SOC0 40 -> between 30 and 50; SOC0 80 -> between 100 and 150.
P3 (proved): per event, the day the floor is reached in simulation >= tfloor_lower_bound_day in floor_time_lower_bound.csv (SOC0 60 median: 5.0 for B=75, 4.0 for B=85/90/100).
P4 (proved, C1+C3, threshold lowered to 0): the bound becomes vacuous (P_upper >= 0.74 at B=50, SOC0 80); a threshold-lowering drain strategy is NOT covered by the current replay and should be tested.

## soc40_actual
```
status  certified  not_certified  sampling_missed   P_upper
B                                                          
10.0          122             10                3  0.074074
20.0          116             16                3  0.118519
30.0           25            107                3  0.792593
50.0            5            127                3  0.940741
75.0            3            129                3  0.955556
85.0            3            129                3  0.955556
90.0            3            129                3  0.955556
100.0           3            129                3  0.955556
150.0           3            129                3  0.955556
200.0           3            129                3  0.955556
NaN             1            131                3  0.970370
```

## soc40_band_lo
```
status  certified  not_certified  sampling_missed   P_upper
B                                                          
10.0          109             23                3  0.170370
20.0           97             35                3  0.259259
30.0           15            117                3  0.866667
50.0            3            129                3  0.955556
75.0            3            129                3  0.955556
85.0            3            129                3  0.955556
90.0            3            129                3  0.955556
100.0           3            129                3  0.955556
150.0           3            129                3  0.955556
200.0           1            131                3  0.970370
NaN             1            131                3  0.970370
```

## soc40_zero
```
status  certified  not_certified  sampling_missed   P_upper
B                                                          
10.0            4            128                3  0.948148
20.0            3            129                3  0.955556
30.0            3            129                3  0.955556
50.0            3            129                3  0.955556
75.0            3            129                3  0.955556
85.0            3            129                3  0.955556
90.0            3            129                3  0.955556
100.0           3            129                3  0.955556
150.0           3            129                3  0.955556
200.0           1            131                3  0.970370
NaN             1            131                3  0.970370
```

## soc60_actual
```
status  certified  not_certified  sampling_missed   P_upper
B                                                          
10.0          131              1                3  0.007407
20.0          129              3                3  0.022222
30.0          126              6                3  0.044444
50.0          125              7                3  0.051852
75.0          114             18                3  0.133333
85.0           15            117                3  0.866667
90.0           15            117                3  0.866667
100.0          13            119                3  0.881481
150.0           5            127                3  0.940741
200.0           3            129                3  0.955556
NaN             2            130                3  0.962963
```

## soc60_band_lo
```
status  certified  not_certified  sampling_missed   P_upper
B                                                          
10.0          125              7                3  0.051852
20.0          125              7                3  0.051852
30.0          123              9                3  0.066667
50.0          120             12                3  0.088889
75.0           92             40                3  0.296296
85.0           11            121                3  0.896296
90.0           11            121                3  0.896296
100.0           8            124                3  0.918519
150.0           3            129                3  0.955556
200.0           3            129                3  0.955556
NaN             2            130                3  0.962963
```

## soc60_zero
```
status  certified  not_certified  sampling_missed   P_upper
B                                                          
10.0           15            117                3  0.866667
20.0           11            121                3  0.896296
30.0            7            125                3  0.925926
50.0            5            127                3  0.940741
75.0            4            128                3  0.948148
85.0            4            128                3  0.948148
90.0            4            128                3  0.948148
100.0           4            128                3  0.948148
150.0           3            129                3  0.955556
200.0           3            129                3  0.955556
NaN             2            130                3  0.962963
```

## soc80_actual
```
status  certified  not_certified  sampling_missed   P_upper
B                                                          
10.0          132              0                3  0.000000
20.0          132              0                3  0.000000
30.0          132              0                3  0.000000
50.0          132              0                3  0.000000
75.0          126              6                3  0.044444
85.0          126              6                3  0.044444
90.0          126              6                3  0.044444
100.0         125              7                3  0.051852
150.0          15            117                3  0.866667
200.0           5            127                3  0.940741
NaN             3            129                3  0.955556
```

## soc80_band_lo
```
status  certified  not_certified  sampling_missed   P_upper
B                                                          
10.0          132              0                3  0.000000
20.0          132              0                3  0.000000
30.0          132              0                3  0.000000
50.0          127              5                3  0.037037
75.0          123              9                3  0.066667
85.0          122             10                3  0.074074
90.0          122             10                3  0.074074
100.0         120             12                3  0.088889
150.0          12            120                3  0.888889
200.0           4            128                3  0.948148
NaN             3            129                3  0.955556
```

## soc80_zero
```
status  certified  not_certified  sampling_missed   P_upper
B                                                          
10.0          130              2                3  0.014815
20.0          130              2                3  0.014815
30.0          128              4                3  0.029630
50.0           32            100                3  0.740741
75.0           15            117                3  0.866667
85.0           11            121                3  0.896296
90.0           10            122                3  0.903704
100.0           5            127                3  0.940741
150.0           5            127                3  0.940741
200.0           4            128                3  0.948148
NaN             3            129                3  0.955556
```

## adaptive threshold in [band_lo, action] (any C1 adversary)
```
 soc0   B  certified  not_certified  sampling_missed  P_upper
   40  10        102             30                3 0.222222
   40  20         87             45                3 0.333333
   40  30          9            123                3 0.911111
   40  50          3            129                3 0.955556
   40  75          3            129                3 0.955556
   40  85          3            129                3 0.955556
   40  90          2            130                3 0.962963
   40 100          2            130                3 0.962963
   60  10        119             13                3 0.096296
   60  20        119             13                3 0.096296
   60  30        118             14                3 0.103704
   60  50        108             24                3 0.177778
   60  75         79             53                3 0.392593
   60  85          9            123                3 0.911111
   60  90          8            124                3 0.918519
   60 100          6            126                3 0.933333
   80  10        125              7                3 0.051852
   80  20        125              7                3 0.051852
   80  30        125              7                3 0.051852
   80  50        120             12                3 0.088889
   80  75        120             12                3 0.088889
   80  85        116             16                3 0.118519
   80  90        113             19                3 0.140741
   80 100        107             25                3 0.185185
```