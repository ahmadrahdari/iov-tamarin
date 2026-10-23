#!/usr/bin/env python3
"""Goal-ranking oracle for the Tamarin proofs of the two-phase IoV protocol.

Tamarin calls the oracle with the name of the lemma being proven as its first
argument and the list of open goals on stdin; the oracle prints the goal
indices in the order in which they should be solved. All rankings solve the
premises of protocol rules and the case distinctions of reused lemmas first.
They differ in the order of the adversary-knowledge goals:

  default  long-term and ephemeral secrets, static-ephemeral DH values,
           authenticators, then encryptions and the remaining DH values;
  secrecy  partner actions and reused lemmas, the NAXOS scalars h(r||sk),
           sigma_1 (which only registered identities can satisfy), then the
           DH values and the session key;
  csf      CS authenticates F_j: follow K_2 = h(Q_2, k_jc, R_1, R_2);
  vcs      V_i authenticates CS: follow N_c and the mask under k_ic;
  basic    fresh names, DH products, encryptions, then the rest.
"""
import sys, re

def isdh(g):
    return (g.startswith('!KU(') and '^' in g and not g.startswith('!KU( h(')
            and not g.startswith('!KU( senc('))

def is_case(g):   # premises, case distinctions of reused lemmas, action goals
    if '▶' in g:
        return True
    if ('∥' in g or g.startswith('(')) and ('Rev' in g or '@' in g or '<' in g or '=' in g):
        return True
    return bool(re.match(r'^[A-Z]\w*\(.*@', g))

def r_default(g):
    if '▶' in g: return 0
    if ('∥' in g or g.startswith('(')) and 'Rev' in g: return 0
    if re.match(r'^Rev\w*\(', g): return 0
    if isdh(g) and '*' in g and re.search(r'~s[fcv]', g): return 1
    if g.startswith('!KU( ~s') or g.startswith('!KU( ~e') or g.startswith('!KU( ~k'): return 1
    if g.startswith('!KU( poly('): return 2
    if re.match(r"^!KU\( h\(<'(sig|sig4|A|d1|d3|d5|nx|SKh|SK)'", g): return 2
    if isdh(g) and '*' in g: return 3
    if g.startswith('!KU( ~'): return 4
    if g.startswith('!KU( senc('): return 5
    if 'splitEqs' in g: return 6
    if isdh(g): return 7
    if g.startswith('!KU( h('): return 8
    return 9

def r_secrecy(g):
    if is_case(g): return 0
    if g.startswith("!KU( h(<'sig'") or g.startswith('!KU( poly('): return 1
    if g.startswith("!KU( h(<'nx'"): return 1
    if (g.startswith('!KU( ~kic') or g.startswith('!KU( ~kjc')
            or g.startswith('!KU( ~s') or g.startswith('!KU( ~e')): return 1
    if isdh(g) and '*' in g: return 2
    if g.startswith("!KU( h(<'SK'"): return 3
    if g.startswith('!KU( senc(') and "'mask'" in g: return 3
    if g.startswith("!KU( h(<'mask'"): return 4
    if 'splitEqs' in g: return 5
    if isdh(g): return 6
    if g.startswith("!KU( h(<'h2'"): return 7
    if g.startswith('!KU( ~'): return 8
    return 9

def r_csf(g):
    if '▶' in g: return 0
    if ('∥' in g or g.startswith('(')) and 'Rev' in g: return 0
    if re.match(r'^Rev\w*\(', g): return 0
    if g.startswith('!KU( senc(') and "'K2'" in g: return 1
    if g.startswith("!KU( h(<'K2'"): return 2
    if g.startswith('!KU( ~kjc') or g.startswith('!KU( ~kic'): return 3
    if g.startswith('!KU( ~s') or g.startswith('!KU( ~e'): return 4
    if 'splitEqs' in g: return 5
    if g.startswith('!KU( senc('): return 6
    if isdh(g) and '*' in g: return 7
    if g.startswith('!KU( ~'): return 9
    if isdh(g): return 8
    if g.startswith('!KU( h('): return 10
    return 8

def r_vcs(g):
    if '▶' in g: return 0
    if ('∥' in g or g.startswith('(')) and 'Rev' in g: return 0
    if re.match(r'^Rev\w*\(', g): return 0
    if g.startswith('!KU( senc(') and "'mask'" in g: return 1
    if g.startswith("!KU( h(<'mask'"): return 2
    if g.startswith('!KU( ~kic') or g.startswith('!KU( ~kjc'): return 3
    if g.startswith("!KU( h(<'d3'") or g.startswith("!KU( h(<'d1'"): return 4
    if g.startswith('!KU( ~s') or g.startswith('!KU( ~e'): return 5
    if isdh(g) and '*' in g and re.search(r'~s[fcv]', g): return 5
    if 'splitEqs' in g: return 6
    if g.startswith("!KU( h(<'SK'"): return 6
    if g.startswith('!KU( senc('): return 7
    if isdh(g) and '*' in g: return 7
    if isdh(g): return 8
    if g.startswith('!KU( ~'): return 9
    if g.startswith('!KU( h('): return 10
    return 8

def r_basic(g):
    if '▶' in g: return 0
    if g.startswith('!KU( ~'): return 1
    if '!KU(' in g and "'g'^(" in g and '*' in g: return 2
    if '!KU(' in g and 'senc(' in g: return 3
    if 'splitEqs' in g: return 4
    if '!KU(' in g and "'g'^" in g: return 5
    if '!KU( poly(' in g: return 7
    if '!KU( h(' in g: return 6
    return 8

RANKING = {
    'eph_V': r_secrecy, 'eph_F': r_secrecy, 'eph_C': r_secrecy,
    'secA_vehicle': r_secrecy, 'secA_fog': r_secrecy, 'secA_cloud': r_secrecy,
    'authA_CS_F': r_csf, 'authA_V_CS': r_vcs, 'secB_vehicle': r_basic,
}

def main():
    lemma = sys.argv[1] if len(sys.argv) > 1 else ''
    rank = RANKING.get(lemma, r_default)
    goals = [l for l in sys.stdin.read().split('\n') if re.match(r'^\d+:', l)]
    order = sorted(range(len(goals)), key=lambda i: (rank(goals[i].split(':', 1)[1].strip()), i))
    for i in order:
        print(goals[i].split(':')[0])

if __name__ == '__main__':
    main()
