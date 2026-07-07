import argparse
from pprint import pprint

import pandas as pd
from sklearn.metrics import classification_report

# Class NAMES only. The data plane numbers classes by cluster deploy order,
# which changes from run to run (sequence and SPP cluster numbering are
# seed/model dependent), so there is no fixed name -> id list: the id map is
# derived per run inside compute_classification_report. A previous version
# hardcoded ids from this list's order, which mislabeled classes whenever the
# deploy order differed (verified against the 40 archived campaign runs).
CLASSES = ['ddos', 'dos', 'normal', 'scanning', 'password', 'xss', 'injection']


def compute_classification_report(results_df, ground_truth_df, classes):
    # Build flow id
    results_df['Flow ID'] = (
        results_df['src_ip'].astype(str) + ' ' +
        results_df['dst_ip'].astype(str) + ' ' +
        results_df['src_port'].astype(str) + ' ' +
        results_df['dst_port'].astype(str) + ' ' +
        results_df['transport_proto'].astype(str)
    )
    results_df['class'] = results_df['class'].astype(int)

    # Merge two dataframes and calculate weight per packet
    labeled = pd.merge(results_df, ground_truth_df, on=['Flow ID'])
    labeled = labeled[labeled['type'].isin(classes)].copy()
    labeled['weight'] = 1 / labeled['packet_counts']

    # Derive the id -> class map for THIS run: each true class takes the id
    # holding most of its flow-weighted mass (id 0 = no verdict, never a class).
    mass = (labeled.pivot_table(index='type', columns='class',
                                values='weight', aggfunc='sum').fillna(0))
    ids = [c for c in mass.columns if c != 0]
    id_of = {t: max(ids, key=lambda i: mass.at[t, i]) for t in mass.index}
    if len(set(id_of.values())) != len(id_of):
        raise SystemExit(f'Derived class-id map is not one-to-one: {id_of}. '
                         'The run is too degenerate to score by majority; inspect it manually.')
    print(f'Derived class-id map (deploy order): {id_of}')
    name_of = {v: k for k, v in id_of.items()}

    # Ids outside the map (0 or stray) count as a miss, never as another class
    labeled['predicted'] = labeled['class'].map(name_of).fillna('none')

    c_report = classification_report(
        labeled['type'],
        labeled['predicted'],
        labels=[t for t in classes if t in mass.index],
        sample_weight=labeled['weight'],
        output_dict=True,
        zero_division=0,
    )
    return c_report


def calculate_score(c_report):
    macro_f1 = c_report['macro avg']['f1-score']
    weighted_f1 = c_report['weighted avg']['f1-score']
    try:
        micro_f1 = c_report['micro avg']['f1-score']
    except KeyError:
        micro_f1 = c_report['accuracy']
    return macro_f1, weighted_f1, micro_f1


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--results", required=True)
    parser.add_argument("--ground-truth", required=True)

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()

    results_df = pd.read_csv(args.results, index_col=None)
    print(f"Collision count: {results_df['collision'].sum()}")
    ground_truth_df = pd.read_csv(args.ground_truth).drop(columns=['Unnamed: 0'], errors='ignore')

    c_report = compute_classification_report(results_df, ground_truth_df, CLASSES)
    pprint(c_report)

    macro_f1, weighted_f1, micro_f1 = calculate_score(c_report)

    print(f"The score information:   Macro={macro_f1} Weighted={weighted_f1} Micro={micro_f1}")
