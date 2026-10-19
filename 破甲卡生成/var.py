# -*- coding: utf-8 -*-
"""Self-variance: same card, same item, N repeats at the same time. Measures how much of a
round-to-round delta could be endpoint drift rather than card effect."""
import sys,io,time,os
sys.path.insert(0,'.')
import sweep as S
HERE=os.path.dirname(os.path.abspath(__file__))
card=io.open(os.path.join(HERE,'..','04-console','cards','base','space-bunny.md'),encoding='utf-8').read()
Q={i:t for i,t in S.ITEMS}
for i in ["E1","E3","E29"]:
    for rep in range(3):
        t0=time.time(); t,rea,us,st=S.raw("space-bunny-free",card,Q[i]); dt=round(time.time()-t0,1)
        v,sig=S.score(i,t,st)
        print("%-4s rep%d %-8s %6.1fs len=%-6d %s"%(i,rep,v,dt,len(t),t[:80].replace('\n',' ')),flush=True)
