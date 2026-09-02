#!/usr/bin/env python3
"""In cac bang so lieu DT/RF ra terminal.

Doc cac tep CSV do ml/plot_binary_results.py sinh ra, khong tinh lai gi.

  python3 ml/report_tables.py --tables output/report_figs/tables
  python3 ml/report_tables.py --tables ... --packets output/ml_final/run7/scada_packets.csv
"""

import argparse
from pathlib import Path

import pandas as pd

W = 94
FAM = {'dt': 'DT', 'rf': 'RF'}


def banner(*lines):
    print('=' * W)
    for l in lines:
        print(l)
    print('=' * W)


def tab(label, desc):
    print(f'\n### {label}  -- {desc}')
    print('-' * W)


def head(cols):
    print(''.join(c for c in cols))
    print('-' * W)


def note(*lines):
    for l in lines:
        print(l)


def load(d, name):
    p = d / f'{name}.csv'
    return pd.read_csv(p) if p.exists() else None


# ---------------------------------------------------------------- tables
def t_dataset(d):
    f = load(d, 't1_dataset_composition')
    if f is None:
        return
    tab('tab:c5-ml-dataset', 'Thanh phan tap du lieu')
    head([f'{"Tap":<12}', f'{"Giao thuc":<9}', f'{"Ban tin":>9}',
          f'{"NORMAL":>9}', f'{"IMPT":>6}', f'{"EMER":>6}',
          f'{"URGENT%":>9}', f'{"Ti le lech":>12}'])
    prev = None
    for _, r in f.iterrows():
        if prev is not None and r['split'] != prev:
            print()
        prev = r['split']
        ir = '--' if r['urgent'] == 0 else f"{int(r['imbalance_ratio'])} : 1"
        print(f"{r['split']:<12}{r['protocol']:<9}{r['messages']:>9,}"
              f"{r['normal']:>9,}{r['important']:>6}{r['emergency']:>6}"
              f"{r['urgent_ratio_pct']:>9.2f}{ir:>12}")
    note('', 'Ti le lech = NORMAL : URGENT trong noi bo tung giao thuc.')


def t_volume(d, packets):
    if not packets:
        return
    p = Path(packets)
    if not p.exists():
        return
    df = pd.read_csv(p, usecols=['direction', 'protocol', 'pkt_size'])
    up = df[df['direction'] == 'uplink']
    g = up.groupby('protocol')['pkt_size'].agg(['count', 'mean', 'sum'])
    g['msg_pct'] = 100 * g['count'] / g['count'].sum()
    g['byte_pct'] = 100 * g['sum'] / g['sum'].sum()
    g = g.sort_values('msg_pct', ascending=False)
    tab('tab:c5-ml-volume', f'Ti trong ban tin vs byte ({p.parent.name})')
    head([f'{"Giao thuc":<10}', f'{"Ban tin":>9}', f'{"Ti trong":>10}',
          f'{"KT trung binh":>14}', f'{"Tong byte":>12}', f'{"Ti trong":>10}'])
    for k, r in g.iterrows():
        print(f'{k:<10}{int(r["count"]):>9,}{r["msg_pct"]:>9.1f}%'
              f'{r["mean"]:>13.0f} B{r["sum"]/1e6:>10.2f} MB'
              f'{r["byte_pct"]:>9.1f}%')
    total = g['count'].sum() * up['pkt_size'].mean() * 8 / 300 / 1e6
    note('', f'Tai uplink trung binh: {total:.2f} Mbps '
             '(access 10 Mbps, core 100 Mbps).')


def t_depth(d):
    f, sel = load(d, 't2_depth_sweep'), load(d, 't5_selected_config')
    if f is None:
        return
    chosen = {}
    if sel is not None:
        chosen = {(r['family'], r['protocol']): r['depth']
                  for _, r in sel.iterrows()}
    tab('tab:c5-ml-depth', 'Quet do sau (F1 macro tren tap kiem dinh)')
    head([f'{"Mo hinh":<12}', f'{"Do sau":>7}', f'{"Acc train":>11}',
          f'{"Acc valid":>11}', f'{"Chenh":>10}', f'{"F1 macro":>10}',
          f'{"Chon":>6}'])
    first = True
    for key, g in f.groupby(['family', 'protocol'], sort=False):
        if not first:
            print()
        first = False
        name = f'{FAM[key[0]]}/{key[1]}'
        # Gop cac do sau cho cung F1 macro thanh mot khoang.
        runs = []
        for _, r in g.sort_values('depth').iterrows():
            k = round(r['f1_macro'], 6)
            if runs and runs[-1][0] == k:
                runs[-1][1].append(r)
            else:
                runs.append((k, [r]))
        for _, rows in runs:
            lo, hi = int(rows[0]['depth']), int(rows[-1]['depth'])
            span = str(lo) if lo == hi else f'{lo}-{hi}'
            pick = chosen.get(key)
            mark = '<--' if pick is not None and lo <= pick <= hi else ''
            r = rows[0]
            print(f'{name:<12}{span:>7}{r["train_acc"]:>11.5f}'
                  f'{r["validation_acc"]:>11.5f}{r["gap"]:>10.5f}'
                  f'{r["f1_macro"]:>10.5f}{mark:>6}')
            name = ''


def t_trees(d):
    f, sel = load(d, 't3_trees_sweep'), load(d, 't5_selected_config')
    if f is None:
        return
    piv = f.pivot_table(index='protocol', columns='trees', values='f1_macro')
    chosen = {}
    if sel is not None:
        chosen = {r['protocol']: r['trees']
                  for _, r in sel[sel['family'] == 'rf'].iterrows()}
    tab('tab:c5-ml-trees', 'Quet so cay RF (F1 macro tren tap kiem dinh)')
    cols = list(piv.columns)
    head([f'{"Giao thuc":<12}'] + [f'{str(c) + " cay":>12}' for c in cols]
         + [f'{"Chon":>8}'])
    for k, r in piv.iterrows():
        vals = ''.join(f'{r[c]:>12.5f}' for c in cols)
        print(f'{k:<12}{vals}{str(chosen.get(k, "")):>8}')


def t_config(d):
    f = load(d, 't5_selected_config')
    if f is None:
        return
    tab('tab:c5-ml-config', 'Cau hinh va nguong duoc chon')
    head([f'{"Mo hinh":<12}', f'{"Do sau":>7}', f'{"So cay":>7}',
          f'{"Mau/la":>7}', f'{"tau":>7}', f'{"F1 macro":>10}',
          f'{"Recall URGENT":>15}'])
    prev = None
    for _, r in f.iterrows():
        if prev is not None and r['family'] != prev:
            print()
        prev = r['family']
        print(f'{FAM[r["family"]] + "/" + r["protocol"]:<12}'
              f'{int(r["depth"]):>7}{int(r["trees"]):>7}{int(r["leaf"]):>7}'
              f'{r["threshold"]:>7.2f}{r["validation_f1_macro"]:>10.5f}'
              f'{r["validation_urgent_recall"]:>15.5f}')


def t_test(d):
    f = load(d, 't8_confusion_binary')
    if f is None:
        return
    tab('tab:c5-ml-test', 'Ma tran nham lan nhi phan, tap kiem tra')
    head([f'{"Thuat toan":<12}', f'{"TP":>6}', f'{"FN":>5}', f'{"FP":>5}',
          f'{"TN":>9}', f'{"Precision":>11}', f'{"Recall":>9}',
          f'{"F1 URGENT":>11}', f'{"Accuracy":>10}'])
    for _, r in f.iterrows():
        print(f'{FAM[r["family"]]:<12}{int(r["TP"]):>6}{int(r["FN"]):>5}'
              f'{int(r["FP"]):>5}{int(r["TN"]):>9,}'
              f'{r["precision_urgent"]:>11.4f}{r["recall_urgent"]:>9.4f}'
              f'{r["f1_urgent"]:>11.4f}{r["accuracy"]:>10.5f}')

    e = load(d, 't9_error_breakdown')
    if e is None or e.empty:
        return
    tab('tab:c5-ml-errors', 'Phan tich mau bi phan loai sai')
    head([f'{"Thuat toan":<12}', f'{"Giao thuc":<10}', f'{"Nhan dung":<11}',
          f'{"Loai ban tin":<14}', f'{"So mau":>7}', f'{"Loai loi":>16}'])
    prev = None
    for _, r in e.sort_values(['family', 'protocol']).iterrows():
        if prev is not None and r['family'] != prev:
            print()
        prev = r['family']
        kind = 'Bo sot' if r['binary_truth'] == 'URGENT' else 'Bao dong gia'
        print(f'{FAM[r["family"]]:<12}{r["protocol"]:<10}'
              f'{r["binary_truth"]:<11}{r["message_kind"]:<14}'
              f'{int(r["count"]):>7}{kind:>16}')


def t_scope(d):
    f = load(d, 't6_test_summary')
    if f is not None:
        tab('tab:c5-ml-scope', 'Mo hinh dung chung vs theo giao thuc')
        head([f'{"Pham vi":<16}', f'{"Thuat toan":<11}', f'{"F1 macro":>10}',
              f'{"F1 URGENT":>11}', f'{"Precision":>11}', f'{"Recall":>9}',
              f'{"Accuracy":>10}'])
        f = f.copy()
        f['scope'] = f['model'].str.contains('pooled').map(
            {True: 'Dung chung', False: 'Theo giao thuc'})
        f['fam'] = f['model'].str.rsplit('_', n=1).str[-1].map(FAM)
        for _, r in f.sort_values(['scope', 'f1_macro'],
                                  ascending=[True, False]).iterrows():
            print(f'{r["scope"]:<16}{r["fam"]:<11}{r["f1_macro"]:>10.5f}'
                  f'{r["f1_urgent"]:>11.5f}{r["urgent_precision"]:>11.5f}'
                  f'{r["urgent_recall"]:>9.5f}{r["accuracy"]:>10.5f}')

    p = load(d, 't7_test_by_protocol')
    if p is None:
        return
    piv = p.pivot_table(index='protocol', columns=['scope', 'family'],
                        values='f1_macro')
    tab('tab:c5-ml-scope-proto', 'F1 macro theo tung giao thuc')
    cols = list(piv.columns)
    head([f'{"Giao thuc":<12}'] +
         [f'{("gop" if c[0] == "pooled" else "rieng") + "/" + FAM[c[1]]:>14}'
          for c in cols])
    for k, r in piv.iterrows():
        best = max((r[c] for c in cols if pd.notna(r[c])), default=None)
        line = ''
        for c in cols:
            v = r[c]
            line += ('    --' + ' ' * 8 if pd.isna(v)
                     else f'{v:>13.4f}' + ('*' if v == best else ' '))
        print(f'{k:<12}{line}')
    note('', '* = gia tri tot nhat cua hang.')


def t_featimp(d):
    f = load(d, 't11_importance_by_group')
    if f is None:
        return
    piv = f.pivot_table(index='group', columns=['family', 'protocol'],
                        values='gini_importance')
    tab('tab:c5-ml-featimp', 'Muc quan trong Gini theo nhom dac trung')
    cols = list(piv.columns)
    head([f'{"Nhom dac trung":<22}'] +
         [f'{FAM[c[0]] + "/" + c[1]:>12}' for c in cols])
    for k, r in piv.iterrows():
        print(f'{k:<22}' + ''.join(f'{r[c]:>12.3f}' for c in cols))


def t_score(d):
    f = load(d, 't12_score_split')
    if f is None:
        return
    tab('tab:c5-ml-score', 'So ban tin hai phia nguong tau')
    head([f'{"Mo hinh":<12}', f'{"Duoi: NORMAL":>14}', f'{"Duoi: URGENT":>14}',
          f'{"Tren: NORMAL":>14}', f'{"Tren: URGENT":>14}'])
    prev = None
    for (fam, proto), g in f.groupby(['family', 'protocol']):
        if prev is not None and fam != prev:
            print()
        prev = fam
        lo = g[g['side'] == 'below'].iloc[0]
        hi = g[g['side'] == 'above'].iloc[0]
        print(f'{FAM[fam] + "/" + proto:<12}{int(lo["normal"]):>14,}'
              f'{int(lo["urgent"]):>14}{int(hi["normal"]):>14}'
              f'{int(hi["urgent"]):>14}')


def t_runtime(d):
    g = load(d, 't13_runtime_gating')
    if g is not None:
        r = g.iloc[0]
        tab('tab:c5-ml-gating', 'Pham vi ban tin duoc dua qua mo hinh')
        head([f'{"Nhom ban tin":<44}', f'{"So ban tin":>14}', f'{"Ti le":>10}'])
        tot = int(r['uplink_messages'])
        for lbl, v in [('Tong so ban tin di len', tot),
                       ('Bi loai: ban tin PROTOCOL',
                        int(r['protocol_messages'])),
                       ('Bi loai: duong co so chua san sang',
                        int(r['baseline_not_ready'])),
                       ('Duoc dua qua mo hinh', int(r['evaluated']))]:
            print(f'{lbl:<44}{v:>14,}{100*v/tot:>9.2f}%')

    b = load(d, 't14_runtime_binary')
    if b is not None:
        tab('tab:c5-ml-runtime', 'Ket qua nhi phan khi chay truc tuyen')
        head([f'{"Thuat toan":<12}', f'{"TP":>6}', f'{"FN":>5}', f'{"FP":>5}',
              f'{"TN":>9}', f'{"Precision":>11}', f'{"Recall":>9}',
              f'{"F1 URGENT":>11}', f'{"F1 macro":>10}'])
        for _, r in b.iterrows():
            print(f'{FAM[r["family"]]:<12}{int(r["TP"]):>6}{int(r["FN"]):>5}'
                  f'{int(r["FP"]):>5}{int(r["TN"]):>9,}'
                  f'{r["precision_urgent"]:>11.4f}{r["recall_urgent"]:>9.4f}'
                  f'{r["f1_urgent"]:>11.4f}{r["f1_macro"]:>10.4f}')

    c = load(d, 't15_runtime_3class')
    if c is not None:
        tab('tab:c5-ml-runtime3', 'Ba lop sau quy tac ngu nghia')
        head([f'{"Thuat toan":<12}', f'{"Lop":<12}', f'{"So mau":>9}',
              f'{"Precision":>11}', f'{"Recall":>10}', f'{"F1":>10}'])
        prev = None
        for _, r in c.iterrows():
            if prev is not None and r['family'] != prev:
                print()
            prev = r['family']
            print(f'{FAM[r["family"]]:<12}{r["traffic_class"]:<12}'
                  f'{int(r["support"]):>9,}{r["precision"]:>11.4f}'
                  f'{r["recall"]:>10.4f}{r["f1"]:>10.4f}')

    p = load(d, 't16_runtime_by_protocol')
    if p is not None:
        tab('tab:c5-ml-runtime-proto', 'Ket qua truc tuyen theo giao thuc')
        head([f'{"Thuat toan":<12}', f'{"Giao thuc":<10}', f'{"So mau":>9}',
              f'{"F1 URGENT":>12}', f'{"Recall URGENT":>15}',
              f'{"Ghi chu":>22}'])
        prev = None
        for _, r in p.iterrows():
            if prev is not None and r['family'] != prev:
                print()
            prev = r['family']
            f1 = '--' if pd.isna(r['f1_urgent']) else f'{r["f1_urgent"]:.4f}'
            rc = '--' if pd.isna(r['recall_urgent']) else f'{r["recall_urgent"]:.4f}'
            nt = '' if pd.isna(r.get('note')) else str(r.get('note') or '')
            print(f'{FAM[r["family"]]:<12}{r["protocol"]:<10}'
                  f'{int(r["support"]):>9,}{f1:>12}{rc:>15}{nt:>22}')


def t_cost(d):
    f = load(d, 't17_model_cost')
    if f is None:
        return
    tab('tab:c5-ml-cost', 'Chi phi trien khai cua mo hinh da xuat')
    head([f'{"Mo hinh":<12}', f'{"Do sau":>7}', f'{"So cay":>7}',
          f'{"tau":>7}', f'{"Kich thuoc":>13}', f'{"So so sanh toi da":>20}'])
    prev = None
    for _, r in f.iterrows():
        if prev is not None and r['family'] != prev:
            print()
        prev = r['family']
        print(f'{FAM[r["family"]] + "/" + r["protocol"]:<12}'
              f'{int(r["depth"]):>7}{int(r["trees"]):>7}{r["threshold"]:>7.2f}'
              f'{r["size_kb"]:>10.1f} KB{int(r["comparisons_worst_case"]):>20}')
    print('-' * W)
    print(f'{"TONG":<12}{"":>7}{"":>7}{"":>7}{f.size_kb.sum():>10.1f} KB'
          f'{"":>20}')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tables', default='output/report_figs/tables')
    ap.add_argument('--packets', help='scada_packets.csv de tinh ti trong byte')
    args = ap.parse_args()
    d = Path(args.tables)
    if not d.is_dir():
        raise SystemExit(f'Khong thay thu muc: {d}')

    n = len(list(d.glob('*.csv')))
    banner(f'BANG SO LIEU DT/RF: {d}',
           f'{n} tep CSV nguon | lop duong = URGENT | tau = nguong quyet dinh')

    for fn in (t_dataset, t_depth, t_trees, t_config, t_test,
               t_scope, t_featimp, t_score, t_runtime, t_cost):
        fn(d)
    t_volume(d, args.packets)
    print()


if __name__ == '__main__':
    main()
