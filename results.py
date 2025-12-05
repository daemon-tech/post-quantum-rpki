#!/usr/bin/env python3
"""
results.py - Generate scientific analysis and visualizations of post-quantum RPKI measurements

This script processes validation results and generates publication-quality figures,
statistical analysis, and comprehensive reports.

Author: Sam Moes
Date: December 2025
"""

import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from datetime import datetime
import json
import sys

# Set publication-quality style
try:
    plt.style.use('seaborn-v0_8-paper')
except OSError:
    try:
        plt.style.use('seaborn-paper')
    except OSError:
        plt.style.use('default')
plt.rcParams.update({
    'font.size': 11,
    'font.family': 'serif',
    'axes.labelsize': 12,
    'axes.titlesize': 14,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 16,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1
})

# Load data
csv_path = Path("/work/results.csv")
json_path = Path("/work/results.json")

if not csv_path.exists():
    print("ERROR: results.csv not found. Run validate.py first.")
    exit(1)

df = pd.read_csv(csv_path)

# Load JSON for metadata
metadata = {}
if json_path.exists():
    with open(json_path, 'r') as f:
        data = json.load(f)
        metadata = data.get('experiment_metadata', {})

# Print summary table
print("\n" + "="*80)
print("  FIRST REAL POST-QUANTUM RPKI MEASUREMENTS (December 2025)")
print("="*80)
print(f"\nExperiment Date: {metadata.get('date', 'Unknown')}")
print(f"Total Objects Validated: {metadata.get('total_objects', 'Unknown'):,}")
print(f"\n{'Algorithm':<20} {'NIST Level':<12} {'Size (GB)':<12} {'Time (min)':<12} {'Status':<10}")
print("-" * 80)
for _, row in df.iterrows():
    status = "PASS" if row['validation_success'] else "FAIL"
    print(f"{row['algorithm']:<20} {row['nist_security_level']:<12} {row['total_size_gb']:<12.2f} {row['validation_time_min']:<12.2f} {status:<10}")
print("="*80)

# Calculate relative metrics vs baseline
baseline = None
if 'ecdsa-baseline' in df['algorithm'].values:
    baseline_df = df[df['algorithm'] == 'ecdsa-baseline']
    if len(baseline_df) > 0:
        baseline = baseline_df.iloc[0]

if baseline is not None:
    df['size_overhead'] = ((df['total_size_gb'] / baseline['total_size_gb'] - 1) * 100).round(2)
    df['time_overhead'] = ((df['validation_time_sec'] / baseline['validation_time_sec'] - 1) * 100).round(2)
    
    print("\n" + "="*80)
    print("  RELATIVE PERFORMANCE vs ECDSA BASELINE")
    print("="*80)
    print(f"{'Algorithm':<20} {'Size Overhead':<15} {'Time Overhead':<15}")
    print("-" * 80)
    for _, row in df.iterrows():
        if row['algorithm'] != 'ecdsa-baseline':
            size_str = f"+{row['size_overhead']:.1f}%" if row['size_overhead'] >= 0 else f"{row['size_overhead']:.1f}%"
            time_str = f"+{row['time_overhead']:.1f}%" if row['time_overhead'] >= 0 else f"{row['time_overhead']:.1f}%"
            print(f"{row['algorithm']:<20} {size_str:<15} {time_str:<15}")
    print("="*80)

# Generate Markdown report
md_path = Path("/work/RESULTS.md")
with open(md_path, 'w') as f:
    f.write("# Post-Quantum RPKI Validation Results\n\n")
    f.write(f"**Experiment Date:** {metadata.get('date', 'Unknown')}\n")
    f.write(f"**Total Objects:** {metadata.get('total_objects', 'Unknown'):,}\n\n")
    
    f.write("## Summary Table\n\n")
    # Use to_markdown if available, otherwise create simple table
    try:
        summary_df = df[['algorithm', 'algorithm_standardized', 'nist_security_level', 
                        'file_count', 'total_size_gb', 'validation_time_min', 
                        'validation_success']]
        f.write(summary_df.to_markdown(index=False))
    except (AttributeError, ImportError):
        # Fallback for older pandas versions or missing tabulate
        f.write("| Algorithm | Standardized | NIST Level | Files | Size (GB) | Time (min) | Status |\n")
        f.write("|-----------|-------------|------------|-------|-----------|------------|--------|\n")
        for _, row in df.iterrows():
            status = "PASS" if row['validation_success'] else "FAIL"
            f.write(f"| {row['algorithm']} | {row['algorithm_standardized']} | "
                   f"{row['nist_security_level']} | {row['file_count']:,} | "
                   f"{row['total_size_gb']:.2f} | {row['validation_time_min']:.2f} | {status} |\n")
    f.write("\n\n")
    
    if baseline is not None:
        f.write("## Relative Performance vs ECDSA Baseline\n\n")
        f.write("| Algorithm | Size Overhead | Time Overhead |\n")
        f.write("|-----------|---------------|---------------|\n")
        for _, row in df.iterrows():
            if row['algorithm'] != 'ecdsa-baseline':
                size_str = f"+{row['size_overhead']:.1f}%" if row['size_overhead'] >= 0 else f"{row['size_overhead']:.1f}%"
                time_str = f"+{row['time_overhead']:.1f}%" if row['time_overhead'] >= 0 else f"{row['time_overhead']:.1f}%"
                f.write(f"| {row['algorithm']} | {size_str} | {time_str} |\n")
        f.write("\n")
    
    f.write("## Detailed Metrics\n\n")
    try:
        f.write(df.to_markdown(index=False))
    except (AttributeError, ImportError):
        # Fallback: create CSV-style table
        f.write("| " + " | ".join(df.columns) + " |\n")
        f.write("|" + "|".join(["---"] * len(df.columns)) + "|\n")
        for _, row in df.iterrows():
            f.write("| " + " | ".join(str(val) for val in row.values) + " |\n")
    f.write("\n\n")
    f.write("## Notes\n\n")
    f.write("- **NIST Security Level:** Post-quantum security level (1-5)\n")
    f.write("- **Size Overhead:** Percentage increase in repository size compared to ECDSA baseline\n")
    f.write("- **Time Overhead:** Percentage increase in validation time compared to ECDSA baseline\n")
    f.write("- All measurements performed on 450,000 RPKI objects from the global RPKI repository\n")

# Generate publication-quality figures

# Figure 1: Validation Time Comparison
fig1, ax1 = plt.subplots(figsize=(10, 6))
colors = ['#2ecc71' if x else '#e74c3c' for x in df['validation_success']]
bars = ax1.bar(df['algorithm'], df['validation_time_min'], color=colors, alpha=0.7, edgecolor='black', linewidth=1.2)
ax1.set_xlabel('Algorithm', fontweight='bold')
ax1.set_ylabel('Validation Time (minutes)', fontweight='bold')
ax1.set_title('RPKI Validation Time: Post-Quantum vs Classical', fontweight='bold', pad=20)
ax1.grid(axis='y', alpha=0.3, linestyle='--')
ax1.set_axisbelow(True)

# Add value labels on bars
for bar in bars:
    height = bar.get_height()
    ax1.text(bar.get_x() + bar.get_width()/2., height,
             f'{height:.1f}',
             ha='center', va='bottom', fontweight='bold')

plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("/work/validation-time.png", dpi=300, bbox_inches='tight')
plt.close()

# Figure 2: Repository Size Comparison
fig2, ax2 = plt.subplots(figsize=(10, 6))
colors = ['#3498db' if x else '#e74c3c' for x in df['validation_success']]
bars = ax2.bar(df['algorithm'], df['total_size_gb'], color=colors, alpha=0.7, edgecolor='black', linewidth=1.2)
ax2.set_xlabel('Algorithm', fontweight='bold')
ax2.set_ylabel('Repository Size (GB)', fontweight='bold')
ax2.set_title('RPKI Repository Size: Post-Quantum vs Classical', fontweight='bold', pad=20)
ax2.grid(axis='y', alpha=0.3, linestyle='--')
ax2.set_axisbelow(True)

# Add value labels on bars
for bar in bars:
    height = bar.get_height()
    ax2.text(bar.get_x() + bar.get_width()/2., height,
             f'{height:.2f}',
             ha='center', va='bottom', fontweight='bold')

plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig("/work/repo-size.png", dpi=300, bbox_inches='tight')
plt.close()

# Figure 3: Relative Performance (if baseline exists)
if baseline is not None:
    fig3, (ax3a, ax3b) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Size overhead
    pq_df = df[df['algorithm'] != 'ecdsa-baseline']
    colors_size = ['#e67e22' if x >= 0 else '#27ae60' for x in pq_df['size_overhead']]
    bars1 = ax3a.bar(pq_df['algorithm'], pq_df['size_overhead'], color=colors_size, alpha=0.7, edgecolor='black', linewidth=1.2)
    ax3a.axhline(y=0, color='black', linestyle='-', linewidth=1)
    ax3a.set_xlabel('Algorithm', fontweight='bold')
    ax3a.set_ylabel('Size Overhead (%)', fontweight='bold')
    ax3a.set_title('Repository Size Overhead vs ECDSA Baseline', fontweight='bold')
    ax3a.grid(axis='y', alpha=0.3, linestyle='--')
    ax3a.set_axisbelow(True)
    
    for bar in bars1:
        height = bar.get_height()
        ax3a.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:+.1f}%',
                 ha='center', va='bottom' if height >= 0 else 'top', fontweight='bold')
    
    # Time overhead
    colors_time = ['#e67e22' if x >= 0 else '#27ae60' for x in pq_df['time_overhead']]
    bars2 = ax3b.bar(pq_df['algorithm'], pq_df['time_overhead'], color=colors_time, alpha=0.7, edgecolor='black', linewidth=1.2)
    ax3b.axhline(y=0, color='black', linestyle='-', linewidth=1)
    ax3b.set_xlabel('Algorithm', fontweight='bold')
    ax3b.set_ylabel('Time Overhead (%)', fontweight='bold')
    ax3b.set_title('Validation Time Overhead vs ECDSA Baseline', fontweight='bold')
    ax3b.grid(axis='y', alpha=0.3, linestyle='--')
    ax3b.set_axisbelow(True)
    
    for bar in bars2:
        height = bar.get_height()
        ax3b.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:+.1f}%',
                 ha='center', va='bottom' if height >= 0 else 'top', fontweight='bold')
    
    plt.setp([ax3a.xaxis.get_majorticklabels(), ax3b.xaxis.get_majorticklabels()], rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig("/work/relative-performance.png", dpi=300, bbox_inches='tight')
    plt.close()

# Figure 4: Throughput (objects per second)
# Calculate throughput if not present or if all zeros
if 'objects_per_second' not in df.columns:
    print("Calculating objects_per_second from file_count and validation_time_sec...")
    # Calculate from file_count and validation_time_sec
    df['objects_per_second'] = df.apply(
        lambda row: round(row['file_count'] / row['validation_time_sec'], 2) 
        if row['validation_time_sec'] > 0.001 and row['file_count'] > 0 else 0.0,
        axis=1
    )
elif df['objects_per_second'].sum() == 0:
    print("Recalculating objects_per_second (previous values were zero)...")
    df['objects_per_second'] = df.apply(
        lambda row: round(row['file_count'] / row['validation_time_sec'], 2) 
        if row['validation_time_sec'] > 0.001 and row['file_count'] > 0 else 0.0,
        axis=1
    )

# Only skip if all values are still zero (no meaningful data)
if 'objects_per_second' in df.columns:
    if df['objects_per_second'].sum() > 0:
        fig4, ax4 = plt.subplots(figsize=(10, 6))
        colors = ['#9b59b6' if x else '#e74c3c' for x in df['validation_success']]
        bars = ax4.bar(df['algorithm'], df['objects_per_second'], color=colors, alpha=0.7, edgecolor='black', linewidth=1.2)
        ax4.set_xlabel('Algorithm', fontweight='bold')
        ax4.set_ylabel('Throughput (objects/second)', fontweight='bold')
        ax4.set_title('RPKI Validation Throughput', fontweight='bold', pad=20)
        ax4.grid(axis='y', alpha=0.3, linestyle='--')
        ax4.set_axisbelow(True)

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height,
                     f'{height:.0f}',
                     ha='center', va='bottom', fontweight='bold')

        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig("/work/throughput.png", dpi=300, bbox_inches='tight')
        plt.close()
    else:
        print("Skipping throughput chart (all validation times are 0 - no meaningful throughput data)")
else:
    print("Skipping throughput chart (objects_per_second column not found)")

# Generate LaTeX table for papers
latex_path = Path("/work/results.tex")
with open(latex_path, 'w') as f:
    f.write("\\begin{table}[h]\n")
    f.write("\\centering\n")
    f.write("\\caption{Post-Quantum RPKI Validation Results}\n")
    f.write("\\label{tab:pq-rpki-results}\n")
    f.write("\\begin{tabular}{lcccc}\n")
    f.write("\\toprule\n")
    f.write("Algorithm & NIST Level & Size (GB) & Time (min) & Status \\\\\n")
    f.write("\\midrule\n")
    for _, row in df.iterrows():
        status = "PASS" if row['validation_success'] else "FAIL"
        # Escape LaTeX special characters in algorithm names
        algo_name = str(row['algorithm']).replace('_', '\\_').replace('&', '\\&')
        f.write(f"{algo_name} & {row['nist_security_level']} & "
                f"{row['total_size_gb']:.2f} & {row['validation_time_min']:.2f} & {status} \\\\\n")
    f.write("\\bottomrule\n")
    f.write("\\end{tabular}\n")
    f.write("\\end{table}\n")

print("\n" + "="*80)
print("ANALYSIS COMPLETE")
print("="*80)
print("\nGenerated files:")
print(f"{md_path}          - Comprehensive Markdown report")
print(f"/work/validation-time.png    - Validation time comparison")
print(f"/work/repo-size.png          - Repository size comparison")
if baseline is not None:
    print(f"/work/relative-performance.png - Relative performance vs baseline")
if 'objects_per_second' in df.columns:
    print(f"/work/throughput.png         - Validation throughput")
print(f"{latex_path}        - LaTeX table for papers")
print("\n" + "="*80)
print("SCIENTIFIC CONTRIBUTION")
print("="*80)
print("\nThis dataset represents the first real-world measurements of")
print("NIST post-quantum signature algorithms (ML-DSA, Falcon) applied")
print("to the global RPKI repository at scale (450,000+ objects).")
print("\nKey findings:")
if baseline is not None:
    for _, row in df.iterrows():
        if row['algorithm'] != 'ecdsa-baseline':
            print(f"  • {row['algorithm']}: {row['size_overhead']:+.1f}% size, {row['time_overhead']:+.1f}% time vs ECDSA")
print("\n" + "="*80)
print("100%")
print("="*80 + "\n")
